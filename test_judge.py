"""Unit tests for judge.py. Run: venv/bin/python -m pytest -q"""
import os
from types import MappingProxyType, SimpleNamespace

import pytest
from typesafe_sdk import Choice, Noul

import judge


@pytest.fixture(autouse=True)
def reset_judge(monkeypatch):
    judge._client = None
    judge._cache.clear()
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)


class FakeClient:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def system_one(self, state, questions):
        self.calls.append((state, questions))
        return self.response


def test_plain_converts_nested_mappings_and_sequences():
    proxy = MappingProxyType({"tags": MappingProxyType({"env": "prod"}), "ports": (22, 443), "name": "x"})
    assert judge.plain(proxy) == {"tags": {"env": "prod"}, "ports": [22, 443], "name": "x"}


def test_plain_leaves_strings_and_scalars_alone():
    assert judge.plain("abc") == "abc"
    assert judge.plain(3) == 3
    assert judge.plain(None) is None


def test_ask_raises_clear_error_without_api_key():
    with pytest.raises(RuntimeError, match="TYPESAFE_API_KEY"):
        judge.ask({"a": 1}, {"q": Noul(instructions="Is a one?")})


def test_ask_caches_identical_requests():
    fake = FakeClient(SimpleNamespace(nouls={"q": SimpleNamespace(noul=0.9)}))
    judge._client = fake
    q = {"q": Noul(instructions="Is a one?")}
    first = judge.ask({"a": 1}, q)
    second = judge.ask({"a": 1}, q)
    assert first is second
    assert len(fake.calls) == 1


def test_ask_does_not_cache_across_different_state():
    fake = FakeClient(SimpleNamespace(nouls={"q": SimpleNamespace(noul=0.9)}))
    judge._client = fake
    q = {"q": Noul(instructions="Is a one?")}
    judge.ask({"a": 1}, q)
    judge.ask({"a": 2}, q)
    assert len(fake.calls) == 2


def test_noul_returns_probability():
    judge._client = FakeClient(SimpleNamespace(nouls={"q": SimpleNamespace(noul=0.42)}))
    assert judge.noul({"a": 1}, "Is a one?") == 0.42


def test_is_public_cidr():
    assert judge.is_public_cidr("0.0.0.0/0")
    assert judge.is_public_cidr("::/0")
    assert not judge.is_public_cidr("10.0.0.0/8")
    assert not judge.is_public_cidr(None)


def test_value_shape_never_includes_the_value():
    secret = "AKIAIOSFODNN7EXAMPLE"
    shape = judge.value_shape(secret)
    assert secret not in str(shape)
    assert shape["length"] == 20
    assert shape["known_prefix"] == "AKIA"
    assert shape["has_spaces"] is False


def test_value_shape_describes_character_classes():
    shape = judge.value_shape("hello world 42!")
    assert shape["has_spaces"] is True
    assert set(shape["classes"]) == {"lowercase", "digits", "symbols"}
    assert shape["known_prefix"] is None


def test_env_class_returns_unknown_without_env_tag():
    assert judge.env_class({"owner": "platform"}) == ("unknown", 1.0)


def test_env_class_asks_choice_over_env_tag_value():
    fake = FakeClient(SimpleNamespace(choices={"env": SimpleNamespace(choice="production", confidence=0.93)}))
    judge._client = fake
    assert judge.env_class({"Environment": "prd-us-east"}) == ("production", 0.93)
    state, questions = fake.calls[0]
    assert state == {"tag_key": "Environment", "tag_value": "prd-us-east"}
    assert isinstance(questions["env"], Choice)
    assert set(questions["env"].criteria) == {"production", "staging", "development", "test", "unknown"}


def test_load_dotenv_sets_key_from_file_next_to_judge(monkeypatch, tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("# comment\nTYPESAFE_API_KEY=from-file\nOTHER=x\n")
    judge.load_dotenv(env_file)
    assert judge.os.environ["TYPESAFE_API_KEY"] == "from-file"


def test_load_dotenv_does_not_override_existing_env(monkeypatch, tmp_path):
    monkeypatch.setenv("TYPESAFE_API_KEY", "from-env")
    env_file = tmp_path / ".env"
    env_file.write_text("TYPESAFE_API_KEY=from-file\n")
    judge.load_dotenv(env_file)
    assert judge.os.environ["TYPESAFE_API_KEY"] == "from-env"


def test_load_dotenv_ignores_missing_file(tmp_path):
    judge.load_dotenv(tmp_path / "nope.env")
