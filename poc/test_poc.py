import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from pulumi_policy.proxy import unknown_checking_proxy

spec = importlib.util.spec_from_file_location("policy_pack", Path(__file__).with_name("__main__.py"))
pack = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pack)

def iam_document(actions):
    return json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": actions, "Resource": "*"},
    ]})


CASES = [
    ("internal_resource_not_public", "aws:ec2/instance:Instance", "reconciliation",
     {"associatePublicIpAddress": True, "tags": {"purpose": "Finance staff reconcile invoices over the company VPN"}}, True),
    ("internal_resource_not_public", "aws:ec2/instance:Instance", "checkout",
     {"associatePublicIpAddress": True, "tags": {"purpose": "Shoppers browse products and pay from their own devices"}}, False),
    ("sg_rule_matches_description", "aws:vpc/securityGroupIngressRule:SecurityGroupIngressRule", "staff-portal",
     {"ipProtocol": "tcp", "fromPort": 443, "toPort": 443, "cidrIpv4": "0.0.0.0/0",
      "description": "TLS access restricted to staff connected through the company VPN"}, True),
    ("sg_rule_matches_description", "aws:vpc/securityGroupIngressRule:SecurityGroupIngressRule", "storefront",
     {"ipProtocol": "tcp", "fromPort": 443, "toPort": 443, "cidrIpv4": "0.0.0.0/0",
      "description": "TLS access for shoppers connecting from anywhere on the internet"}, False),
    ("iam_grant_matches_stated_purpose", "aws:iam/policy:Policy", "metrics-reader",
     {"description": "Read CloudWatch metrics for the operations dashboard",
      "policy": iam_document(["cloudwatch:*", "ec2:*"])}, True),
    ("iam_grant_matches_stated_purpose", "aws:iam/policy:Policy", "metrics-viewer",
     {"description": "Read CloudWatch metrics for the operations dashboard",
      "policy": iam_document(["cloudwatch:GetMetricData", "cloudwatch:ListMetrics"])}, False),
]


def evaluate(function, resource_type, name, props):
    messages = []
    args = SimpleNamespace(resource_type=resource_type, name=name,
                           props=unknown_checking_proxy(props))
    next(p for p in pack.POLICIES if p.name == function.replace("_", "-")).validate(args, messages.append)
    return messages


def test_three_policies_in_one_file():
    assert hasattr(pack, "POLICIES"), "Policy definitions must live in __main__.py"
    assert len(pack.POLICIES) == 3
    assert {p.name for p in pack.POLICIES} == {case[0].replace("_", "-") for case in CASES}


@pytest.mark.parametrize("function,resource_type,name,props,expected", CASES)
@pytest.mark.parametrize("probability", [0.79, 0.8, 0.99])
def test_threshold_and_sdk_state(monkeypatch, function, resource_type, name, props, expected, probability):
    client = MagicMock()
    client.system_one.return_value = SimpleNamespace(nouls={"q": SimpleNamespace(noul=probability)})
    factory = MagicMock()
    factory.return_value.__enter__.return_value = client
    monkeypatch.setattr(pack, "TypeSafeClient", factory)
    messages = evaluate(function, resource_type, name, props)
    assert bool(messages) == (probability >= 0.8)
    state = client.system_one.call_args.kwargs["state"]
    assert state["name"] == name
    assert state["tags"] == props.get("tags", {})
    assert isinstance(state["tags"], dict)
    assert state["description"] == props.get("description")
    if function == "sg_rule_matches_description":
        assert state["source_is_anywhere"] is True
        assert state["protocol"] == "tcp"
        assert state["ports"] == [443, 443]
    if function == "iam_grant_matches_stated_purpose":
        assert state["statements"] == json.loads(props["policy"])["Statement"]


@pytest.mark.parametrize("function,resource_type,props", [
    ("internal_resource_not_public", "aws:ec2/instance:Instance", {"associatePublicIpAddress": False}),
    ("sg_rule_matches_description", "aws:vpc/securityGroupIngressRule:SecurityGroupIngressRule", {"cidrIpv4": "10.0.0.0/8"}),
    ("iam_grant_matches_stated_purpose", "aws:iam/policy:Policy", {"policy": '{"Statement": []}'}),
])
def test_configured_resources_skip_ai(monkeypatch, function, resource_type, props):
    def unexpected_call(*args, **kwargs):
        pytest.fail("No AI call needed for an exact field check")
    monkeypatch.setattr(pack, "TypeSafeClient", unexpected_call)
    assert evaluate(function, resource_type, "internal-work-logs", props) == []
    assert evaluate(function, "pulumi:pulumi:Stack", "demo", {}) == []


@pytest.mark.skipif(os.environ.get("RUN_LIVE") != "1", reason="Set RUN_LIVE=1 and TYPESAFE_API_KEY")
@pytest.mark.parametrize("function,resource_type,name,props,expected", CASES)
def test_live(function, resource_type, name, props, expected):
    messages = evaluate(function, resource_type, name, props)
    print(f"{name}: {messages or 'pass'}")
    assert bool(messages) == expected


def test_public_ingress_without_description_is_decided_in_code(monkeypatch):
    monkeypatch.setattr(pack, "TypeSafeClient", lambda: pytest.fail("No AI needed"))
    messages = evaluate("sg_rule_matches_description",
        "aws:vpc/securityGroupIngressRule:SecurityGroupIngressRule", "rule", {"cidrIpv6": "::/0"})
    assert len(messages) == 1
    assert "description" in messages[0]
