"""Thin wrapper around the TypeSafe client: one place for the API key, caching, and shared judgments."""
import json
import os
import string
from collections.abc import Mapping, Sequence
from pathlib import Path

from typesafe_sdk import Choice, Noul, TypeSafeClient

DEFAULT = 0.8
HIGH = 0.85

_client = None
_cache = {}

_KNOWN_SECRET_PREFIXES = ("AKIA", "ASIA", "ghp_", "gho_", "github_pat_", "sk-", "xoxb-", "xoxp-", "AIza", "-----BEGIN", "glpat-")
_ENV_TAG_KEYS = ("env", "environment", "stage")
ENV_CRITERIA = {
    "production": "Serves real users or real data: prod, prd, production, live",
    "staging": "Pre-production rehearsal of production: staging, stg, preprod, uat",
    "development": "Engineer sandboxes and feature work: dev, development, sandbox",
    "test": "Automated or manual testing: test, qa, ci, integration",
    "unknown": "The value does not identify an environment",
}


def load_dotenv(path=Path(__file__).with_name(".env")):
    if not Path(path).is_file():
        return
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip("'\""))


def _get_client():
    global _client
    if _client is None:
        load_dotenv()
        if not os.environ.get("TYPESAFE_API_KEY"):
            raise RuntimeError("TYPESAFE_API_KEY is not set. The typesafe-aws-policies pack needs it to evaluate policies.")
        _client = TypeSafeClient()
    return _client


def plain(value):
    if isinstance(value, Mapping):
        return {str(k): plain(v) for k, v in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return [plain(v) for v in value]
    return value


def ask(state, questions):
    state = plain(state)
    key = (json.dumps(state, sort_keys=True, default=str), tuple(sorted(questions)))
    if key not in _cache:
        _cache[key] = _get_client().system_one(state, questions)
    return _cache[key]


def noul(state, instructions, criteria=None):
    return ask(state, {"q": Noul(instructions=instructions, criteria=criteria)}).nouls["q"].noul


def noul_each(state, key, instructions, criteria=None):
    """Ask the same yes/no question about every item in state[key] in one request. `{i}` in instructions is the index."""
    items = state[key]
    if not items:
        return []
    questions = {f"{key}_{i}": Noul(instructions=instructions.format(i=i), criteria=criteria) for i in range(len(items))}
    answers = ask(state, questions).nouls
    return [answers[f"{key}_{i}"].noul for i in range(len(items))]


def is_public_cidr(cidr):
    return cidr in ("0.0.0.0/0", "::/0")


def value_shape(value):
    classes = []
    if any(c in string.ascii_uppercase for c in value):
        classes.append("uppercase")
    if any(c in string.ascii_lowercase for c in value):
        classes.append("lowercase")
    if any(c in string.digits for c in value):
        classes.append("digits")
    if any(c in string.punctuation for c in value):
        classes.append("symbols")
    return {
        "length": len(value),
        "classes": classes,
        "has_spaces": any(c.isspace() for c in value),
        "known_prefix": next((p for p in _KNOWN_SECRET_PREFIXES if value.startswith(p)), None),
        "looks_like_url": value.startswith(("http://", "https://")),
        "looks_like_arn": value.startswith("arn:"),
    }


def env_tag(tags):
    tag_key = next((k for k in tags if k.lower() in _ENV_TAG_KEYS), None)
    return None if tag_key is None else (tag_key, tags[tag_key])


def env_class(tags):
    found = env_tag(tags)
    if found is None:
        return ("unknown", 1.0)
    tag_key, tag_value = found
    answer = ask(
        {"tag_key": tag_key, "tag_value": tag_value},
        {"env": Choice(instructions="Which environment does the tag `tag_value` identify?", criteria=ENV_CRITERIA)},
    ).choices["env"]
    return (answer.choice, answer.confidence)
