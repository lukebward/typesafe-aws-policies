import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from pulumi_policy.proxy import unknown_checking_proxy

spec = importlib.util.spec_from_file_location("policy_pack", Path(__file__).with_name("__main__.py"))
pack = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pack)

CASES = [
    ("internal_resource_not_public", "aws:ec2/instance:Instance",
     "admin-console", {"associatePublicIpAddress": True}, True),
    ("internal_resource_not_public", "aws:ec2/instance:Instance",
     "public-web", {"associatePublicIpAddress": True}, False),
    ("log_and_temp_buckets_have_lifecycle", "aws:s3/bucket:Bucket",
     "access-logs", {}, True),
    ("log_and_temp_buckets_have_lifecycle", "aws:s3/bucket:Bucket",
     "permanent-uploads", {}, False),
    ("sqs_work_queue_has_dlq", "aws:sqs/queue:Queue",
     "order-processing", {}, True),
    ("sqs_work_queue_has_dlq", "aws:sqs/queue:Queue",
     "order-processing-dlq", {}, False),
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
    messages = evaluate(function, resource_type, name, props | {"tags": {"purpose": "demo"}})
    assert bool(messages) == (probability >= 0.8)
    state = client.system_one.call_args.kwargs["state"]
    assert state["name"] == name
    assert state["tags"] == {"purpose": "demo"}
    assert isinstance(state["tags"], dict)


@pytest.mark.parametrize("function,resource_type,props", [
    ("internal_resource_not_public", "aws:ec2/instance:Instance", {"associatePublicIpAddress": False}),
    ("log_and_temp_buckets_have_lifecycle", "aws:s3/bucket:Bucket", {"lifecycleRules": [{"enabled": True, "expiration": {"days": 30}}]}),
    ("sqs_work_queue_has_dlq", "aws:sqs/queue:Queue", {"redrivePolicy": '{"deadLetterTargetArn":"arn:aws:sqs:us-west-2:123456789012:dlq","maxReceiveCount":5}'}),
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
