"""Unit tests for the 15 policies with a fake TypeSafe client. Run: venv/bin/python -m pytest -q"""
import json
from types import MappingProxyType, SimpleNamespace

import pytest
from pulumi_policy import EnforcementLevel, Severity
from typesafe_sdk import Choice, Noul, Score

import judge
import policies


class FakeAsk:
    """Answers every question with canned values; a dict for nouls answers per question id."""

    def __init__(self, noul=0.0, choice=("unknown", 1.0), score=2.0):
        self.noul, self.choice, self.score = noul, choice, score
        self.calls = []

    def __call__(self, state, questions):
        self.calls.append((judge.plain(state), questions))
        nouls, choices, scores = {}, {}, {}
        for k, q in questions.items():
            if isinstance(q, Noul):
                nouls[k] = SimpleNamespace(noul=self.noul[k] if isinstance(self.noul, dict) else self.noul)
            elif isinstance(q, Choice):
                choices[k] = SimpleNamespace(choice=self.choice[0], confidence=self.choice[1])
            elif isinstance(q, Score):
                scores[k] = SimpleNamespace(score=self.score)
        return SimpleNamespace(nouls=nouls, choices=choices, scores=scores)


@pytest.fixture
def fake(monkeypatch):
    f = FakeAsk()
    monkeypatch.setattr(judge, "ask", f)
    return f


def run(fn, resource_type, props, name="res"):
    out = []
    args = SimpleNamespace(resource_type=resource_type, props=MappingProxyType(props), name=name, urn=f"urn::{name}")
    fn(args, lambda m, urn=None: out.append(m))
    return out


def statements(*stmts):
    return json.dumps({"Version": "2012-10-17", "Statement": list(stmts)})


# 1
def test_s3_bucket_policy_not_public_reports_when_model_says_public(fake):
    fake.noul = 0.95
    pol = statements({"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"})
    msgs = run(policies.s3_bucket_policy_not_public, "aws:s3/bucketPolicy:BucketPolicy", {"policy": pol})
    assert len(msgs) == 1 and "0.95" in msgs[0]
    assert fake.calls[0][0] == {"statements": json.loads(pol)["Statement"]}


def test_s3_bucket_policy_not_public_passes_when_model_says_private(fake):
    fake.noul = 0.1
    pol = statements({"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::1:root"}, "Action": "s3:GetObject", "Resource": "*"})
    assert run(policies.s3_bucket_policy_not_public, "aws:s3/bucketPolicy:BucketPolicy", {"policy": pol}) == []


def test_s3_bucket_policy_not_public_ignores_other_types(fake):
    assert run(policies.s3_bucket_policy_not_public, "aws:s3/bucket:Bucket", {"policy": "{}"}) == []
    assert fake.calls == []


# 2
def test_s3_sensitive_bucket_encrypted_reports_unencrypted_sensitive_bucket(fake):
    fake.noul = 0.9
    msgs = run(policies.s3_sensitive_bucket_encrypted, "aws:s3/bucket:Bucket", {"bucket": "customer-pii-exports", "tags": {"owner": "data"}})
    assert len(msgs) == 1
    assert fake.calls[0][0] == {"bucket_name": "customer-pii-exports", "tags": {"owner": "data"}}


def test_s3_sensitive_bucket_encrypted_skips_when_encryption_configured(fake):
    props = {"bucket": "customer-pii-exports", "serverSideEncryptionConfiguration": {"rule": {}}}
    assert run(policies.s3_sensitive_bucket_encrypted, "aws:s3/bucket:Bucket", props) == []
    assert fake.calls == []


def test_s3_sensitive_bucket_encrypted_skips_bucket_v2_which_has_no_encryption_input(fake):
    assert run(policies.s3_sensitive_bucket_encrypted, "aws:s3/bucketV2:BucketV2", {"bucket": "customer-pii-exports"}) == []
    assert fake.calls == []


def test_s3_sensitive_bucket_encrypted_uses_resource_name_when_bucket_unset(fake):
    fake.noul = 0.2
    run(policies.s3_sensitive_bucket_encrypted, "aws:s3/bucket:Bucket", {}, name="logs")
    assert fake.calls[0][0]["bucket_name"] == "logs"


# 3
def test_iam_no_admin_equivalent_reports_escalation_path(fake):
    fake.noul = 0.92
    pol = statements({"Effect": "Allow", "Action": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"], "Resource": "*"})
    msgs = run(policies.iam_no_admin_equivalent, "aws:iam/policy:Policy", {"policy": pol})
    assert len(msgs) == 1 and "0.92" in msgs[0]


def test_iam_no_admin_equivalent_passes_scoped_policy(fake):
    fake.noul = 0.05
    pol = statements({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"})
    assert run(policies.iam_no_admin_equivalent, "aws:iam/rolePolicy:RolePolicy", {"policy": pol}) == []


# 4
def test_iam_mutating_actions_scoped_reports_wildcard_mutations(fake):
    fake.noul = 0.9
    pol = statements({"Effect": "Allow", "Action": ["ec2:TerminateInstances"], "Resource": "*"})
    msgs = run(policies.iam_mutating_actions_scoped, "aws:iam/policy:Policy", {"policy": pol})
    assert len(msgs) == 1
    assert fake.calls[0][0] == {"actions": ["ec2:TerminateInstances"]}


def test_iam_mutating_actions_scoped_skips_when_resources_are_scoped(fake):
    pol = statements({"Effect": "Allow", "Action": ["ec2:TerminateInstances"], "Resource": "arn:aws:ec2:*:*:instance/i-1"})
    assert run(policies.iam_mutating_actions_scoped, "aws:iam/policy:Policy", {"policy": pol}) == []
    assert fake.calls == []


def test_iam_mutating_actions_scoped_passes_read_only_wildcard(fake):
    fake.noul = 0.1
    pol = statements({"Effect": "Allow", "Action": ["ec2:Describe*"], "Resource": ["*"]})
    assert run(policies.iam_mutating_actions_scoped, "aws:iam/policy:Policy", {"policy": pol}) == []


# 5
def test_iam_trust_policy_restricted_reports_open_trust(fake):
    fake.noul = 0.97
    trust = statements({"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"})
    msgs = run(policies.iam_trust_policy_restricted, "aws:iam/role:Role", {"assumeRolePolicy": trust})
    assert len(msgs) == 1
    assert fake.calls[0][0] == {"statements": json.loads(trust)["Statement"]}


def test_iam_trust_policy_restricted_passes_service_trust(fake):
    fake.noul = 0.02
    trust = statements({"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"})
    assert run(policies.iam_trust_policy_restricted, "aws:iam/role:Role", {"assumeRolePolicy": trust}) == []


# 6
def test_iam_no_service_users_reports_machine_identity(fake):
    fake.noul = 0.9
    msgs = run(policies.iam_no_service_users, "aws:iam/user:User", {"name": "ci-deploy-bot"})
    assert len(msgs) == 1
    assert fake.calls[0][0] == {"user_name": "ci-deploy-bot"}


def test_iam_no_service_users_passes_person(fake):
    fake.noul = 0.1
    assert run(policies.iam_no_service_users, "aws:iam/user:User", {"name": "jane.doe"}) == []


# 7
def test_sg_no_public_admin_ports_reports_public_ssh(fake):
    fake.noul = 0.96
    props = {"ingress": [{"fromPort": 22, "toPort": 22, "protocol": "tcp", "cidrBlocks": ["0.0.0.0/0"], "description": "ssh"}]}
    msgs = run(policies.sg_no_public_admin_ports, "aws:ec2/securityGroup:SecurityGroup", props)
    assert len(msgs) == 1 and "22" in msgs[0]


def test_sg_no_public_admin_ports_skips_private_rules(fake):
    props = {"ingress": [{"fromPort": 22, "toPort": 22, "protocol": "tcp", "cidrBlocks": ["10.0.0.0/8"]}]}
    assert run(policies.sg_no_public_admin_ports, "aws:ec2/securityGroup:SecurityGroup", props) == []
    assert fake.calls == []


def test_sg_no_public_admin_ports_asks_all_public_rules_in_one_request(fake):
    fake.noul = {"rule_0": 0.95, "rule_1": 0.05}
    props = {"ingress": [
        {"fromPort": 3389, "toPort": 3389, "protocol": "tcp", "cidrBlocks": ["0.0.0.0/0"]},
        {"fromPort": 443, "toPort": 443, "protocol": "tcp", "ipv6CidrBlocks": ["::/0"]},
    ]}
    msgs = run(policies.sg_no_public_admin_ports, "aws:ec2/securityGroup:SecurityGroup", props)
    assert len(msgs) == 1 and "3389" in msgs[0]
    assert len(fake.calls) == 1


def test_sg_no_public_admin_ports_handles_standalone_ingress_rule(fake):
    fake.noul = 0.9
    props = {"type": "ingress", "fromPort": 5432, "toPort": 5432, "protocol": "tcp", "cidrBlocks": ["0.0.0.0/0"]}
    assert len(run(policies.sg_no_public_admin_ports, "aws:ec2/securityGroupRule:SecurityGroupRule", props)) == 1
    assert run(policies.sg_no_public_admin_ports, "aws:ec2/securityGroupRule:SecurityGroupRule", {**props, "type": "egress"}) == []


# 8
def test_sg_description_meaningful_reports_placeholder(fake):
    fake.score = 0.2
    msgs = run(policies.sg_description_meaningful, "aws:ec2/securityGroup:SecurityGroup", {"description": "Managed by Pulumi"})
    assert len(msgs) == 1
    assert isinstance(fake.calls[0][1]["quality"], Score)


def test_sg_description_meaningful_passes_clear_description(fake):
    fake.score = 1.9
    assert run(policies.sg_description_meaningful, "aws:ec2/securityGroup:SecurityGroup", {"description": "Allows HTTPS from the ALB to the API pods"}) == []


# 9
def test_ec2_no_public_ip_in_prod_reports_prod_public_instance(fake):
    fake.choice = ("production", 0.9)
    props = {"associatePublicIpAddress": True, "tags": {"env": "prd"}}
    assert len(run(policies.ec2_no_public_ip_in_prod, "aws:ec2/instance:Instance", props)) == 1


def test_ec2_no_public_ip_in_prod_passes_dev_public_instance(fake):
    fake.choice = ("development", 0.9)
    props = {"associatePublicIpAddress": True, "tags": {"env": "dev"}}
    assert run(policies.ec2_no_public_ip_in_prod, "aws:ec2/instance:Instance", props) == []


def test_ec2_no_public_ip_in_prod_skips_without_public_ip(fake):
    assert run(policies.ec2_no_public_ip_in_prod, "aws:ec2/instance:Instance", {"tags": {"env": "prod"}}) == []
    assert fake.calls == []


# 10
def test_rds_prod_not_public_reports_public_prod_db(fake):
    fake.choice = ("production", 0.95)
    props = {"publiclyAccessible": True, "tags": {"Environment": "production"}}
    assert len(run(policies.rds_prod_not_public, "aws:rds/instance:Instance", props)) == 1


def test_rds_prod_not_public_skips_private_db(fake):
    assert run(policies.rds_prod_not_public, "aws:rds/cluster:Cluster", {"publiclyAccessible": False, "tags": {"env": "prod"}}) == []
    assert fake.calls == []


# 11
def test_rds_prod_backups_and_protection_reports_both_gaps(fake):
    fake.choice = ("production", 0.9)
    props = {"backupRetentionPeriod": 1, "deletionProtection": False, "tags": {"env": "prod"}}
    msgs = run(policies.rds_prod_backups_and_protection, "aws:rds/instance:Instance", props)
    assert len(msgs) == 2


def test_rds_prod_backups_and_protection_treats_missing_retention_as_default(fake):
    fake.choice = ("production", 0.9)
    msgs = run(policies.rds_prod_backups_and_protection, "aws:rds/instance:Instance", {"deletionProtection": True, "tags": {"env": "prod"}})
    assert len(msgs) == 1 and "backupRetentionPeriod" in msgs[0]


def test_rds_prod_backups_and_protection_passes_hardened_prod(fake):
    fake.choice = ("production", 0.9)
    props = {"backupRetentionPeriod": 7, "deletionProtection": True, "tags": {"env": "prod"}}
    assert run(policies.rds_prod_backups_and_protection, "aws:rds/instance:Instance", props) == []


def test_rds_prod_backups_and_protection_ignores_non_prod(fake):
    fake.choice = ("development", 0.9)
    props = {"backupRetentionPeriod": 0, "deletionProtection": False, "tags": {"env": "dev"}}
    assert run(policies.rds_prod_backups_and_protection, "aws:rds/instance:Instance", props) == []


# 12
def test_lambda_no_plaintext_secrets_reports_only_flagged_vars(fake):
    fake.noul = {"var_0": 0.95, "var_1": 0.03}
    props = {"environment": {"variables": {"DB_PASSWORD": "hunter2hunter2", "LOG_LEVEL": "info"}}}
    msgs = run(policies.lambda_no_plaintext_secrets, "aws:lambda/function:Function", props)
    assert len(msgs) == 1 and "DB_PASSWORD" in msgs[0]


def test_lambda_no_plaintext_secrets_never_sends_values(fake):
    fake.noul = 0.0
    props = {"environment": {"variables": {"DB_PASSWORD": "hunter2hunter2"}}}
    run(policies.lambda_no_plaintext_secrets, "aws:lambda/function:Function", props)
    assert "hunter2" not in json.dumps(fake.calls[0][0])
    assert fake.calls[0][0]["variables"][0]["name"] == "DB_PASSWORD"


def test_lambda_no_plaintext_secrets_skips_without_env(fake):
    assert run(policies.lambda_no_plaintext_secrets, "aws:lambda/function:Function", {}) == []
    assert fake.calls == []


# 13
def test_tags_owner_is_real_reports_placeholder(fake):
    fake.noul = 0.9
    msgs = run(policies.tags_owner_is_real, "aws:s3/bucket:Bucket", {"tags": {"owner": "todo"}})
    assert len(msgs) == 1 and "todo" in msgs[0]


def test_tags_owner_is_real_passes_real_owner(fake):
    fake.noul = 0.05
    assert run(policies.tags_owner_is_real, "aws:s3/bucket:Bucket", {"tags": {"Owner": "platform-team"}}) == []


def test_tags_owner_is_real_skips_missing_owner_and_control_plane(fake):
    assert run(policies.tags_owner_is_real, "aws:s3/bucket:Bucket", {"tags": {"env": "prod"}}) == []
    assert run(policies.tags_owner_is_real, "pulumiservice:index:Stack", {"tags": {"owner": "todo"}}) == []
    assert fake.calls == []


# 14
def test_tags_env_recognized_reports_unknown(fake):
    fake.choice = ("unknown", 0.8)
    assert len(run(policies.tags_env_recognized, "aws:s3/bucket:Bucket", {"tags": {"env": "banana"}})) == 1


def test_tags_env_recognized_reports_low_confidence(fake):
    fake.choice = ("staging", 0.4)
    assert len(run(policies.tags_env_recognized, "aws:s3/bucket:Bucket", {"tags": {"env": "p"}})) == 1


def test_tags_env_recognized_passes_clear_env(fake):
    fake.choice = ("production", 0.95)
    assert run(policies.tags_env_recognized, "aws:s3/bucket:Bucket", {"tags": {"env": "prod"}}) == []


def test_tags_env_recognized_skips_without_env_tag(fake):
    assert run(policies.tags_env_recognized, "aws:s3/bucket:Bucket", {"tags": {"owner": "x"}}) == []
    assert fake.calls == []


# 15
def test_resource_name_descriptive_reports_placeholder_name(fake):
    fake.noul = 0.9
    msgs = run(policies.resource_name_descriptive, "aws:s3/bucket:Bucket", {}, name="test123")
    assert len(msgs) == 1 and "test123" in msgs[0]
    assert fake.calls[0][0] == {"resource_type": "aws:s3/bucket:Bucket", "name": "test123"}


def test_resource_name_descriptive_skips_stack_and_providers(fake):
    assert run(policies.resource_name_descriptive, "pulumi:pulumi:Stack", {}, name="x") == []
    assert run(policies.resource_name_descriptive, "pulumi:providers:aws", {}, name="default") == []
    assert fake.calls == []


# registry
def test_registry_has_fifteen_unique_documented_policies():
    names = [p.name for p in policies.POLICIES]
    assert len(names) == 15 and len(set(names)) == len(names)
    for p in policies.POLICIES:
        assert p.validate.__doc__
        assert isinstance(p.enforcement, EnforcementLevel)
        assert isinstance(p.severity, Severity)
