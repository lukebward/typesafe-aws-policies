"""Tests for the state audit runner. Run: venv/bin/python -m pytest -q test_audit.py"""
import json
from types import SimpleNamespace

import pytest
from typesafe_sdk import Noul

import audit
import judge


@pytest.fixture
def fake(monkeypatch):
    def ask(state, questions):
        return SimpleNamespace(nouls={k: SimpleNamespace(noul=0.9) for k, q in questions.items() if isinstance(q, Noul)}, choices={}, scores={})
    monkeypatch.setattr(judge, "ask", ask)


def state_with(*resources):
    return {"deployment": {"resources": [{"urn": f"urn:pulumi:dev::proj::{t}::{n}", "type": t, "inputs": inputs} for t, n, inputs in resources]}}


def test_audit_reports_violations_and_passes_per_applicable_policy(fake):
    rows = audit.audit(state_with(("aws:iam/user:User", "ci-bot", {"name": "ci-deploy-bot"}),
                                  ("kubernetes:core/v1:ConfigMap", "cm", {"data": {}})), config={})
    by_policy = {(r.resource, r.policy): r for r in rows}
    assert by_policy[("ci-bot", "iam-no-service-users")].violations
    assert by_policy[("ci-bot", "tags-meaningful")].violations == [] and by_policy[("ci-bot", "tags-meaningful")].applicable is False
    assert not any(r.resource == "cm" and r.applicable for r in rows)


def test_audit_passes_policy_config(fake):
    trust = json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999999999999:root"}, "Action": "sts:AssumeRole"}]})
    rows = audit.audit(state_with(("aws:iam/role:Role", "r", {"assumeRolePolicy": trust})), config={"iam-trust-account-wide": {"ownAccountId": "999999999999"}})
    assert [r for r in rows if r.policy == "iam-trust-account-wide"][0].violations == []


def test_audit_skips_deleted_and_provider_resources(fake):
    s = state_with(("pulumi:providers:aws", "default", {}), ("aws:iam/user:User", "u", {"name": "ci-deploy-bot"}))
    s["deployment"]["resources"][1]["delete"] = True
    assert audit.audit(s, config={}) == []
