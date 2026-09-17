"""Run every policy over an exported stack state and print each verdict, passes included.

Usage: venv/bin/python audit.py --stack org/stack [--config policy-config.json]
       pulumi stack export | venv/bin/python audit.py [--config policy-config.json]
"""
import argparse
import json
import subprocess
import sys
from collections import Counter
from types import SimpleNamespace
from typing import NamedTuple

from pulumi_policy.proxy import unknown_checking_proxy

import policies


class Row(NamedTuple):
    resource: str
    resource_type: str
    policy: str
    applicable: bool
    violations: list


class _NotApplicable(Exception):
    pass


def audit(state, config):
    rows = []
    for res in state["deployment"]["resources"]:
        rtype = res.get("type", "")
        if res.get("delete") or rtype.startswith("pulumi:"):
            continue
        name = res["urn"].split("::")[-1]
        for rule in policies.POLICIES:
            out = []

            def not_applicable(reason=None):
                raise _NotApplicable(reason)

            args = SimpleNamespace(resource_type=rtype, props=unknown_checking_proxy(res.get("inputs") or {}), name=name, urn=res["urn"],
                                   get_config=lambda r=rule: config.get(r.name) or {}, not_applicable=not_applicable)
            applicable = True
            try:
                rule.validate(args, lambda m, urn=None: out.append(m))
            except _NotApplicable:
                applicable = False
            applicable = applicable and (bool(out) or _touched(rule, rtype, args))
            rows.append(Row(name, rtype, rule.name, applicable, out))
    return rows


def _touched(rule, rtype, args):
    """A policy counts as applicable when its resource-type filter matches and its required inputs exist."""
    fn = rule.validate.__name__
    if fn in ("tags_meaningful", "name_consistent_with_config"):
        return isinstance(args.props.get("tags"), dict) or hasattr(args.props.get("tags"), "items")
    return rtype in policies.APPLICABLE_TYPES.get(fn, ())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--stack")
    parser.add_argument("--config")
    args = parser.parse_args()
    if args.stack:
        state = json.loads(subprocess.check_output(["pulumi", "stack", "export", "--stack", args.stack]))
    else:
        state = json.load(sys.stdin)
    config = json.load(open(args.config)) if args.config else {}
    rows = [r for r in audit(state, config) if r.applicable]
    counts = Counter(r.policy for r in rows)
    print(f"{len({r.resource for r in rows})} resources evaluated, {len(rows)} policy checks, {sum(1 for r in rows if r.violations)} violations\n")
    for row in rows:
        mark = "FAIL" if row.violations else "pass"
        print(f"{mark}  {row.policy:34} {row.resource_type:40} {row.resource}")
        for v in row.violations:
            print(f"      {v}")
    print("\nchecks per policy: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))


if __name__ == "__main__":
    main()
