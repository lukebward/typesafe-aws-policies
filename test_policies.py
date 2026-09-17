"""Unit tests for the 15 policies with a fake TypeSafe client. Run: venv/bin/python -m pytest -q"""
import json
from types import MappingProxyType, SimpleNamespace

import pytest
from pulumi_policy import EnforcementLevel, Severity
from pulumi_policy.proxy import unknown_checking_proxy
from typesafe_sdk import Choice, Noul, Score

import judge
import policies


class FakeAsk:
    """Answers every question with canned values. Pass a dict keyed by question id for per-question answers."""

    def __init__(self, noul=0.0, choice=("unknown", 1.0), score=2.0):
        self.noul, self.choice, self.score = noul, choice, score
        self.calls = []

    @staticmethod
    def _pick(value, key):
        return value[key] if isinstance(value, dict) else value

    def __call__(self, state, questions):
        self.calls.append((judge.plain(state), questions))
        nouls, choices, scores = {}, {}, {}
        for k, q in questions.items():
            if isinstance(q, Noul):
                nouls[k] = SimpleNamespace(noul=self._pick(self.noul, k))
            elif isinstance(q, Choice):
                label, confidence = self._pick(self.choice, k)
                choices[k] = SimpleNamespace(choice=label, confidence=confidence)
            elif isinstance(q, Score):
                scores[k] = SimpleNamespace(score=self._pick(self.score, k))
        return SimpleNamespace(nouls=nouls, choices=choices, scores=scores)


@pytest.fixture
def fake(monkeypatch):
    f = FakeAsk()
    monkeypatch.setattr(judge, "ask", f)
    return f


class NotApplicable(Exception):
    pass


def run(fn, resource_type, props, name="res", config=None):
    out = []

    def not_applicable(reason=None):
        raise NotApplicable(reason)

    args = SimpleNamespace(resource_type=resource_type, props=unknown_checking_proxy(dict(props)), name=name, urn=f"urn::{name}",
                           get_config=lambda: config or {}, not_applicable=not_applicable)
    fn(args, lambda m, urn=None: out.append(m))
    return out


def doc(*stmts):
    return json.dumps({"Version": "2012-10-17", "Statement": list(stmts)})


BUCKET_POLICY = "aws:s3/bucketPolicy:BucketPolicy"
ORG_CONDITION = {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}}
TLS_CONDITION = {"Bool": {"aws:SecureTransport": "true"}}


# 1 resource-policy-not-open
def test_resource_policy_wildcard_without_condition_is_reported_by_code(fake):
    pol = doc({"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"})
    msgs = run(policies.resource_policy_not_open, BUCKET_POLICY, {"policy": pol})
    assert len(msgs) == 1 and fake.calls == []


def test_resource_policy_wildcard_with_weak_condition_reported_by_model(fake):
    fake.noul = 0.9
    stmt = {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*", "Condition": TLS_CONDITION}
    msgs = run(policies.resource_policy_not_open, BUCKET_POLICY, {"policy": doc(stmt)})
    assert len(msgs) == 1 and "0.90" in msgs[0]
    assert fake.calls[0][0] == {"statements": [stmt]}


def test_resource_policy_wildcard_with_strong_condition_passes(fake):
    fake.noul = 0.05
    stmt = {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*", "Condition": ORG_CONDITION}
    assert run(policies.resource_policy_not_open, BUCKET_POLICY, {"policy": doc(stmt)}) == []
    assert len(fake.calls) == 1


def test_resource_policy_specific_principal_skips_model(fake):
    stmt = {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123:role/r"}, "Action": "s3:GetObject", "Resource": "*"}
    assert run(policies.resource_policy_not_open, BUCKET_POLICY, {"policy": doc(stmt)}) == []
    assert fake.calls == []


def test_resource_policy_covers_kms_sqs_sns_secrets(fake):
    open_stmt = doc({"Effect": "Allow", "Principal": {"AWS": ["*"]}, "Action": "kms:Decrypt", "Resource": "*"})
    for rtype in ("aws:kms/key:Key", "aws:sqs/queuePolicy:QueuePolicy", "aws:sns/topicPolicy:TopicPolicy", "aws:secretsmanager/secretPolicy:SecretPolicy"):
        assert len(run(policies.resource_policy_not_open, rtype, {"policy": open_stmt})) == 1, rtype
    assert run(policies.resource_policy_not_open, "aws:kms/key:Key", {}) == []
    assert fake.calls == []


# 2 sensitive-data-store-encrypted
def test_sensitive_store_unencrypted_rds_reported(fake):
    fake.noul = 0.9
    props = {"identifier": "customer-pii-db-7f3a1c2", "storageEncrypted": False, "tags": {"team": "data"}}
    msgs = run(policies.sensitive_data_store_encrypted, "aws:rds/instance:Instance", props, name="customer-pii-db")
    assert len(msgs) == 1
    state = fake.calls[0][0]
    assert state["resource_type"] == "aws:rds/instance:Instance" and state["name"] == "customer-pii-db" and state["tags"] == {"team": "data"}


def test_sensitive_store_encrypted_rds_skips_model(fake):
    assert run(policies.sensitive_data_store_encrypted, "aws:rds/cluster:Cluster", {"storageEncrypted": True}) == []
    assert fake.calls == []


def test_sensitive_store_dynamodb_ebs_efs_s3_fields(fake):
    fake.noul = 0.9
    assert run(policies.sensitive_data_store_encrypted, "aws:dynamodb/table:Table", {"serverSideEncryption": {"enabled": True}}) == []
    assert len(run(policies.sensitive_data_store_encrypted, "aws:dynamodb/table:Table", {"name": "patients"})) == 1
    assert run(policies.sensitive_data_store_encrypted, "aws:ebs/volume:Volume", {"encrypted": True}) == []
    assert len(run(policies.sensitive_data_store_encrypted, "aws:efs/fileSystem:FileSystem", {"encrypted": False})) == 1
    assert run(policies.sensitive_data_store_encrypted, "aws:s3/bucket:Bucket", {"serverSideEncryptionConfiguration": {"rule": {}}}) == []


def test_sensitive_store_non_sensitive_passes(fake):
    fake.noul = 0.1
    assert run(policies.sensitive_data_store_encrypted, "aws:ebs/volume:Volume", {"encrypted": False}, name="scratch-volume") == []


# 3 prod-or-sensitive-store-protected
def test_store_protected_reports_every_gap_on_prod_rds(fake):
    fake.choice, fake.noul = ("production", 0.9), 0.2
    props = {"backupRetentionPeriod": 1, "deletionProtection": False, "multiAz": False, "tags": {"env": "prod"}}
    msgs = run(policies.prod_or_sensitive_store_protected, "aws:rds/instance:Instance", props)
    assert len(msgs) == 3 and len(fake.calls) == 1
    questions = fake.calls[0][1]
    assert isinstance(questions["env"], Choice) and isinstance(questions["sensitive"], Noul)


def test_store_protected_hardened_rds_skips_model(fake):
    props = {"backupRetentionPeriod": 7, "deletionProtection": True, "multiAz": True, "tags": {"env": "prod"}}
    assert run(policies.prod_or_sensitive_store_protected, "aws:rds/instance:Instance", props) == []
    assert fake.calls == []


def test_store_protected_dev_and_not_sensitive_passes(fake):
    fake.choice, fake.noul = ("development", 0.9), 0.1
    props = {"backupRetentionPeriod": 0, "deletionProtection": False, "tags": {"env": "dev"}}
    assert run(policies.prod_or_sensitive_store_protected, "aws:rds/cluster:Cluster", props) == []


def test_store_protected_sensitive_without_env_tag_reports(fake):
    fake.noul = 0.9
    msgs = run(policies.prod_or_sensitive_store_protected, "aws:s3/bucket:Bucket", {"bucket": "customer-pii-exports"})
    assert len(msgs) == 1 and "versioning" in msgs[0]
    assert "env" not in fake.calls[0][1]


def test_store_protected_dynamodb_pitr_and_cluster_multi_az_not_required(fake):
    fake.choice, fake.noul = ("production", 0.9), 0.1
    assert len(run(policies.prod_or_sensitive_store_protected, "aws:dynamodb/table:Table", {"tags": {"env": "prod"}})) == 1
    assert run(policies.prod_or_sensitive_store_protected, "aws:dynamodb/table:Table", {"pointInTimeRecovery": {"enabled": True}, "tags": {"env": "prod"}}) == []
    props = {"backupRetentionPeriod": 7, "deletionProtection": True, "tags": {"env": "prod"}}
    assert run(policies.prod_or_sensitive_store_protected, "aws:rds/cluster:Cluster", props) == []


# 4 iam-no-admin-equivalent
IAM_POLICY = "aws:iam/policy:Policy"


def test_admin_star_on_star_reported_by_code(fake):
    pol = doc({"Effect": "Allow", "Action": "*", "Resource": "*"})
    assert len(run(policies.iam_no_admin_equivalent, IAM_POLICY, {"policy": pol})) == 1
    assert fake.calls == []


def test_admin_known_escalation_chains_reported_by_code(fake):
    passrole_compute = doc({"Effect": "Allow", "Action": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"], "Resource": "*"})
    policy_versions = doc({"Effect": "Allow", "Action": ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"], "Resource": "*"})
    iam_wildcard = doc({"Effect": "Allow", "Action": "iam:*", "Resource": "*"})
    not_action = doc({"Effect": "Allow", "NotAction": ["s3:*"], "Resource": "*"})
    for pol in (passrole_compute, policy_versions, iam_wildcard, not_action):
        assert len(run(policies.iam_no_admin_equivalent, "aws:iam/userPolicy:UserPolicy", {"policy": pol})) == 1, pol
    assert fake.calls == []


def test_admin_passrole_with_unknown_service_wildcard_asks_model(fake):
    fake.noul = 0.9
    pol = doc({"Effect": "Allow", "Action": ["iam:PassRole", "batch:*"], "Resource": "*"})
    msgs = run(policies.iam_no_admin_equivalent, IAM_POLICY, {"policy": pol})
    assert len(msgs) == 1 and "batch" in msgs[0]
    assert fake.calls[0][0]["services"] == ["batch"]


def test_admin_passrole_with_harmless_service_passes(fake):
    fake.noul = 0.1
    pol = doc({"Effect": "Allow", "Action": ["iam:PassRole", "route53:*"], "Resource": "*"})
    assert run(policies.iam_no_admin_equivalent, IAM_POLICY, {"policy": pol}) == []
    assert len(fake.calls) == 1


def test_admin_compute_without_passrole_and_scoped_policies_skip_model(fake):
    for pol in (doc({"Effect": "Allow", "Action": "lambda:*", "Resource": "*"}),
                doc({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}),
                doc({"Effect": "Allow", "Action": ["iam:PassRole", "lambda:CreateFunction"], "Resource": "arn:aws:iam::1:role/one"})):
        assert run(policies.iam_no_admin_equivalent, "aws:iam/groupPolicy:GroupPolicy", {"policy": pol}) == [], pol
    assert fake.calls == []


# 5 iam-grant-matches-stated-purpose
def test_grant_far_beyond_purpose_reported(fake):
    fake.score = 1.9
    pol = doc({"Effect": "Allow", "Action": ["cloudwatch:*", "ec2:*"], "Resource": "*"})
    props = {"name": "read-metrics", "description": "Read CloudWatch metrics for the dashboard", "policy": pol}
    msgs = run(policies.iam_grant_matches_stated_purpose, "aws:iam/policy:Policy", props)
    assert len(msgs) == 1
    state, questions = fake.calls[0]
    assert state["policy_name"] == "read-metrics" and state["description"].startswith("Read CloudWatch")
    assert state["statements"] == json.loads(pol)["Statement"]
    assert isinstance(questions["fit"], Score)


def test_grant_matching_purpose_passes(fake):
    fake.score = 0.2
    pol = doc({"Effect": "Allow", "Action": ["cloudwatch:GetMetricData"], "Resource": "*"})
    assert run(policies.iam_grant_matches_stated_purpose, "aws:iam/policy:Policy", {"name": "read-metrics", "description": "Read metrics", "policy": pol}) == []


def test_grant_role_policy_uses_name_when_no_description(fake):
    fake.score = 0.5
    pol = doc({"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"})
    run(policies.iam_grant_matches_stated_purpose, "aws:iam/rolePolicy:RolePolicy", {"policy": pol}, name="artifact-reader")
    assert fake.calls[0][0]["policy_name"] == "artifact-reader" and fake.calls[0][0]["description"] is None


# 6 iam-trust-policy-restricted
ROLE = "aws:iam/role:Role"
GITHUB = "arn:aws:iam::123:oidc-provider/token.actions.githubusercontent.com"


def test_trust_wildcard_without_condition_reported_by_code(fake):
    trust = doc({"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"})
    assert len(run(policies.iam_trust_policy_restricted, ROLE, {"assumeRolePolicy": trust})) == 1
    assert fake.calls == []


def test_trust_service_principal_skips_model(fake):
    trust = doc({"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"})
    assert run(policies.iam_trust_policy_restricted, ROLE, {"assumeRolePolicy": trust}) == []
    assert fake.calls == []


def test_trust_account_wide_without_own_account_config_is_advisory_only(fake):
    stmt = {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999999999999:root"}, "Action": "sts:AssumeRole"}
    props = {"assumeRolePolicy": doc(stmt)}
    assert run(policies.iam_trust_policy_restricted, ROLE, props) == []
    msgs = run(policies.iam_trust_account_wide, ROLE, props)
    assert len(msgs) == 1 and "999999999999" in msgs[0] and "ownAccountId" in msgs[0]
    assert fake.calls == []


def test_trust_same_account_root_is_silent_when_own_account_configured(fake):
    stmt = {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999999999999:root"}, "Action": "sts:AssumeRole"}
    props, config = {"assumeRolePolicy": doc(stmt)}, {"ownAccountId": "999999999999"}
    assert run(policies.iam_trust_policy_restricted, ROLE, props, config=config) == []
    assert run(policies.iam_trust_account_wide, ROLE, props, config=config) == []
    assert fake.calls == []


def test_trust_cross_account_root_is_mandatory_when_own_account_configured(fake):
    for principal, cond in (("arn:aws:iam::111111111111:root", None), ("111111111111", None), ("arn:aws:iam::111111111111:root", {"Bool": {"aws:SecureTransport": "true"}})):
        stmt = {"Effect": "Allow", "Principal": {"AWS": principal}, "Action": "sts:AssumeRole"}
        if cond:
            stmt["Condition"] = cond
        msgs = run(policies.iam_trust_policy_restricted, ROLE, {"assumeRolePolicy": doc(stmt)}, config={"ownAccountId": "999999999999"})
        assert len(msgs) == 1 and "111111111111" in msgs[0], principal
    assert fake.calls == []


def test_trust_listed_trusted_account_is_allowed(fake):
    stmt = {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::111111111111:root"}, "Action": "sts:AssumeRole"}
    config = {"ownAccountId": "999999999999", "trustedAccountIds": ["111111111111"]}
    assert run(policies.iam_trust_policy_restricted, ROLE, {"assumeRolePolicy": doc(stmt)}, config=config) == []
    assert run(policies.iam_trust_account_wide, ROLE, {"assumeRolePolicy": doc(stmt)}, config=config) == []


def test_trust_named_role_principal_without_condition_passes_without_model(fake):
    stmt = {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999:role/deployer"}, "Action": "sts:AssumeRole"}
    assert run(policies.iam_trust_policy_restricted, ROLE, {"assumeRolePolicy": doc(stmt)}) == []
    assert fake.calls == []


def test_trust_oidc_wildcard_subject_reported_by_model(fake):
    fake.noul = 0.9
    stmt = {"Effect": "Allow", "Principal": {"Federated": GITHUB}, "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {"StringLike": {"token.actions.githubusercontent.com:sub": "repo:acme/*:*"}}}
    msgs = run(policies.iam_trust_policy_restricted, ROLE, {"assumeRolePolicy": doc(stmt)})
    assert len(msgs) == 1
    state = fake.calls[0][0]["statements"][0]
    assert state["principal_kind"] == "federated" and state["condition_keys"] == ["token.actions.githubusercontent.com:sub"]


def test_trust_cross_account_with_external_id_goes_to_model_and_passes(fake):
    fake.noul = 0.1
    stmt = {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999999999999:root"}, "Action": "sts:AssumeRole", "Condition": {"StringEquals": {"sts:ExternalId": "vendor-42"}}}
    assert run(policies.iam_trust_policy_restricted, ROLE, {"assumeRolePolicy": doc(stmt)}) == []
    assert fake.calls[0][0]["statements"][0]["principal_kind"] == "aws-account"


# unknown documents during preview
def test_unknown_policy_document_marks_policy_not_applicable(fake):
    from pulumi_policy.proxy import UNKNOWN_STRING_VALUE
    for fn, rtype, key in ((policies.iam_no_admin_equivalent, IAM_POLICY, "policy"),
                           (policies.iam_grant_matches_stated_purpose, IAM_POLICY, "policy"),
                           (policies.iam_trust_policy_restricted, ROLE, "assumeRolePolicy"),
                           (policies.iam_trust_account_wide, ROLE, "assumeRolePolicy"),
                           (policies.resource_policy_not_open, BUCKET_POLICY, "policy")):
        with pytest.raises(NotApplicable, match="preview"):
            run(fn, rtype, {key: UNKNOWN_STRING_VALUE})
    assert fake.calls == []


# 7 iam-no-service-users
def test_service_user_reported(fake):
    fake.noul = 0.9
    msgs = run(policies.iam_no_service_users, "aws:iam/user:User", {"name": "ci-deploy-bot"})
    assert len(msgs) == 1 and fake.calls[0][0] == {"user_name": "ci-deploy-bot"}


def test_person_user_passes(fake):
    fake.noul = 0.1
    assert run(policies.iam_no_service_users, "aws:iam/user:User", {"name": "jane.doe"}) == []


# 8 sg-rule-matches-description
SG = "aws:ec2/securityGroup:SecurityGroup"


def test_sg_rule_broader_than_description_reported(fake):
    fake.noul = 0.95
    props = {"ingress": [{"fromPort": 0, "toPort": 65535, "protocol": "-1", "cidrBlocks": ["0.0.0.0/0"], "description": "HTTPS from the ALB"}]}
    msgs = run(policies.sg_rule_matches_description, SG, props)
    assert len(msgs) == 1 and "HTTPS from the ALB" in msgs[0]


def test_sg_public_rule_without_description_reported_by_code(fake):
    props = {"ingress": [{"fromPort": 443, "toPort": 443, "protocol": "tcp", "cidrBlocks": ["0.0.0.0/0"]}]}
    assert len(run(policies.sg_rule_matches_description, SG, props)) == 1
    assert fake.calls == []


def test_sg_private_narrow_rule_skips_model(fake):
    props = {"ingress": [{"fromPort": 443, "toPort": 443, "protocol": "tcp", "cidrBlocks": ["10.0.0.0/8"]}]}
    assert run(policies.sg_rule_matches_description, SG, props) == []
    assert fake.calls == []


def test_sg_private_broad_rule_with_honest_description_passes(fake):
    fake.noul = 0.1
    props = {"ingress": [{"fromPort": 0, "toPort": 0, "protocol": "-1", "cidrBlocks": ["10.0.0.0/8"], "description": "All traffic inside the VPC"}]}
    assert run(policies.sg_rule_matches_description, SG, props) == []
    assert len(fake.calls) == 1


def test_sg_rules_fan_out_in_one_request(fake):
    fake.noul = {"rule_0": 0.9, "rule_1": 0.1}
    props = {"ingress": [
        {"fromPort": 0, "toPort": 65535, "protocol": "tcp", "cidrBlocks": ["0.0.0.0/0"], "description": "SSH for ops"},
        {"fromPort": 443, "toPort": 443, "protocol": "tcp", "ipv6CidrBlocks": ["::/0"], "description": "Public HTTPS"},
    ]}
    msgs = run(policies.sg_rule_matches_description, SG, props)
    assert len(msgs) == 1 and "SSH for ops" in msgs[0] and len(fake.calls) == 1


def test_sg_vpc_ingress_rule_resource_supported(fake):
    fake.noul = 0.2
    props = {"cidrIpv4": "0.0.0.0/0", "fromPort": 22, "toPort": 22, "ipProtocol": "tcp", "description": "SSH from the office"}
    assert run(policies.sg_rule_matches_description, "aws:vpc/securityGroupIngressRule:SecurityGroupIngressRule", props) == []
    assert fake.calls[0][0]["rules"][0]["fromPort"] == 22


def test_sg_float_ports_are_rendered_as_integers(fake):
    props = {"ingress": [{"fromPort": 22.0, "toPort": 22.0, "protocol": "tcp", "cidrBlocks": ["0.0.0.0/0"]}]}
    msgs = run(policies.sg_rule_matches_description, SG, props)
    assert "22-22" in msgs[0] and "22.0" not in msgs[0]


# 9 sg-description-meaningful
def test_sg_description_placeholder_reported(fake):
    fake.score = 0.2
    msgs = run(policies.sg_description_meaningful, SG, {"description": "Managed by Pulumi"})
    assert len(msgs) == 1 and isinstance(fake.calls[0][1]["quality"], Score)


def test_sg_description_clear_passes(fake):
    fake.score = 1.9
    assert run(policies.sg_description_meaningful, SG, {"description": "Allows HTTPS from the ALB to the API service"}) == []


# 10 internal-resource-not-public
def test_internal_ec2_with_public_ip_reported(fake):
    fake.noul = 0.9
    msgs = run(policies.internal_resource_not_public, "aws:ec2/instance:Instance", {"associatePublicIpAddress": True, "tags": {"role": "admin"}}, name="admin-console")
    assert len(msgs) == 1 and fake.calls[0][0]["name"] == "admin-console"


def test_private_ec2_skips_model(fake):
    assert run(policies.internal_resource_not_public, "aws:ec2/instance:Instance", {"associatePublicIpAddress": False}) == []
    assert fake.calls == []


def test_load_balancer_defaults_to_external(fake):
    fake.noul = 0.9
    assert len(run(policies.internal_resource_not_public, "aws:lb/loadBalancer:LoadBalancer", {}, name="backoffice-api")) == 1
    assert run(policies.internal_resource_not_public, "aws:lb/loadBalancer:LoadBalancer", {"internal": True}, name="backoffice-api") == []


def test_function_url_without_auth(fake):
    fake.noul = 0.9
    assert len(run(policies.internal_resource_not_public, "aws:lambda/functionUrl:FunctionUrl", {"authorizationType": "NONE", "functionName": "internal-report-generator"})) == 1
    assert fake.calls[0][0]["name"] == "internal-report-generator"
    assert run(policies.internal_resource_not_public, "aws:lambda/functionUrl:FunctionUrl", {"authorizationType": "AWS_IAM", "functionName": "x"}) == []


def test_public_rds_that_looks_public_facing_passes(fake):
    fake.noul = 0.1
    assert run(policies.internal_resource_not_public, "aws:rds/instance:Instance", {"publiclyAccessible": True}, name="public-demo-db") == []


# 11 log-and-temp-buckets-have-lifecycle
def test_log_bucket_without_lifecycle_reported(fake):
    fake.noul = 0.9
    assert len(run(policies.log_and_temp_buckets_have_lifecycle, "aws:s3/bucket:Bucket", {"bucket": "alb-access-logs"})) == 1


def test_bucket_with_lifecycle_skips_model(fake):
    assert run(policies.log_and_temp_buckets_have_lifecycle, "aws:s3/bucket:Bucket", {"bucket": "alb-access-logs", "lifecycleRules": [{"enabled": True}]}) == []
    assert fake.calls == []


def test_durable_bucket_passes(fake):
    fake.noul = 0.1
    assert run(policies.log_and_temp_buckets_have_lifecycle, "aws:s3/bucket:Bucket", {"bucket": "customer-uploads"}) == []


# 12 no-plaintext-secrets-in-env
def test_lambda_env_flags_only_secret_like_vars(fake):
    fake.noul = {"var_0": 0.95, "var_1": 0.03}
    props = {"environment": {"variables": {"DB_PASSWORD": "hunter2hunter2", "LOG_LEVEL": "info"}}}
    msgs = run(policies.no_plaintext_secrets_in_env, "aws:lambda/function:Function", props)
    assert len(msgs) == 1 and "DB_PASSWORD" in msgs[0]
    assert "hunter2" not in json.dumps(fake.calls[0][0])


def test_ecs_task_definition_env_parsed_from_json(fake):
    fake.noul = 0.95
    containers = json.dumps([{"name": "api", "environment": [{"name": "STRIPE_SECRET_KEY", "value": "sk-live-abc123def456"}]}])
    msgs = run(policies.no_plaintext_secrets_in_env, "aws:ecs/taskDefinition:TaskDefinition", {"containerDefinitions": containers})
    assert len(msgs) == 1 and "api" in msgs[0] and "STRIPE_SECRET_KEY" in msgs[0]
    assert "sk-live" not in json.dumps(fake.calls[0][0])


def test_codebuild_skips_secret_store_references(fake):
    fake.noul = 0.95
    env = {"environmentVariables": [
        {"name": "GITHUB_TOKEN", "value": "ghp_abcdefghijklmnop", "type": "PLAINTEXT"},
        {"name": "NPM_TOKEN", "value": "/build/npm-token", "type": "PARAMETER_STORE"},
    ]}
    msgs = run(policies.no_plaintext_secrets_in_env, "aws:codebuild/project:Project", {"environment": env})
    assert len(msgs) == 1 and "GITHUB_TOKEN" in msgs[0]
    assert len(fake.calls[0][0]["variables"]) == 1


def test_no_env_skips_model(fake):
    assert run(policies.no_plaintext_secrets_in_env, "aws:lambda/function:Function", {}) == []
    assert fake.calls == []


# 13 tags-meaningful
def test_tags_meaningful_reports_each_bad_tag_from_one_request(fake):
    fake.noul, fake.choice = {"owner": 0.9, "cost_center": 0.9}, ("unknown", 0.9)
    msgs = run(policies.tags_meaningful, "aws:s3/bucket:Bucket", {"tags": {"owner": "todo", "env": "banana", "cost-center": "n/a"}})
    assert len(msgs) == 3 and len(fake.calls) == 1


def test_tags_meaningful_good_tags_pass(fake):
    fake.noul, fake.choice = 0.1, ("production", 0.9)
    assert run(policies.tags_meaningful, "aws:s3/bucket:Bucket", {"tags": {"Owner": "platform-team", "Environment": "prod"}}) == []


def test_tags_meaningful_low_confidence_env_reported(fake):
    fake.choice = ("staging", 0.4)
    assert len(run(policies.tags_meaningful, "aws:s3/bucket:Bucket", {"tags": {"env": "p"}})) == 1


def test_tags_meaningful_skips_without_relevant_tags_or_on_control_plane(fake):
    assert run(policies.tags_meaningful, "aws:s3/bucket:Bucket", {"tags": {"team": "x"}}) == []
    assert run(policies.tags_meaningful, "pulumiservice:index:Stack", {"tags": {"owner": "todo"}}) == []
    assert fake.calls == []


# 14 name-consistent-with-config
def test_name_env_contradicts_tag_reported(fake):
    fake.choice = {"name_env": ("production", 0.9), "tag_env": ("development", 0.9)}
    msgs = run(policies.name_consistent_with_config, "aws:rds/instance:Instance", {"tags": {"env": "dev"}}, name="prod-orders-db")
    assert len(msgs) == 1 and "prod-orders-db" in msgs[0]


def test_name_without_env_hint_passes(fake):
    fake.choice = {"name_env": ("none", 0.9), "tag_env": ("development", 0.9)}
    assert run(policies.name_consistent_with_config, "aws:rds/instance:Instance", {"tags": {"env": "dev"}}, name="orders-db") == []


def test_name_env_agrees_or_uncertain_passes(fake):
    fake.choice = {"name_env": ("production", 0.9), "tag_env": ("production", 0.9)}
    assert run(policies.name_consistent_with_config, "aws:rds/instance:Instance", {"tags": {"env": "prod"}}, name="prod-orders-db") == []
    fake.choice = {"name_env": ("production", 0.4), "tag_env": ("development", 0.9)}
    assert run(policies.name_consistent_with_config, "aws:rds/instance:Instance", {"tags": {"env": "dev"}}, name="prd-orders-db") == []


def test_name_dev_and_test_are_compatible(fake):
    fake.choice = {"name_env": ("test", 0.9), "tag_env": ("development", 0.9)}
    assert run(policies.name_consistent_with_config, "aws:ebs/volume:Volume", {"tags": {"env": "dev"}}, name="ci-scratch") == []


def test_name_without_env_tag_skips_model(fake):
    assert run(policies.name_consistent_with_config, "aws:rds/instance:Instance", {"tags": {"owner": "x"}}, name="prod-orders-db") == []
    assert fake.calls == []


# 15 sqs-work-queue-has-dlq
def test_work_queue_without_dlq_reported(fake):
    fake.noul = 0.9
    assert len(run(policies.sqs_work_queue_has_dlq, "aws:sqs/queue:Queue", {"name": "order-processing"})) == 1


def test_queue_with_redrive_skips_model(fake):
    assert run(policies.sqs_work_queue_has_dlq, "aws:sqs/queue:Queue", {"name": "order-processing", "redrivePolicy": "{}"}) == []
    assert fake.calls == []


def test_dead_letter_queue_itself_passes(fake):
    fake.noul = 0.1
    assert run(policies.sqs_work_queue_has_dlq, "aws:sqs/queue:Queue", {"name": "order-processing-dlq"}) == []


# registry
def test_registry_has_fifteen_unique_documented_policies():
    names = [p.name for p in policies.POLICIES]
    assert len(names) == 16 and len(set(names)) == 16
    assert policies.POLICIES_BY_NAME["iam-trust-policy-restricted"].config_schema is not None
    assert policies.POLICIES_BY_NAME["iam-trust-account-wide"].config_schema is not None
    for p in policies.POLICIES:
        assert p.validate.__doc__
        assert isinstance(p.enforcement, EnforcementLevel)
        assert isinstance(p.severity, Severity)


# display names: explicit physical names are honored, Pulumi auto-names fall back to the logical name
def test_display_name_prefers_explicit_physical_name(fake):
    fake.noul = 0.9
    msgs = run(policies.iam_no_service_users, "aws:iam/user:User", {"name": "deploy.bot"}, name="ci-user")
    assert "deploy.bot" in msgs[0]


def test_display_name_strips_pulumi_autoname_suffix(fake):
    fake.noul = 0.9
    msgs = run(policies.iam_no_service_users, "aws:iam/user:User", {"name": "ci-deploy-bot-f5676fc"}, name="ci-deploy-bot")
    assert "ci-deploy-bot" in msgs[0] and "f5676fc" not in msgs[0]
    assert fake.calls[0][0] == {"user_name": "ci-deploy-bot"}


def test_grant_purpose_uses_logical_name_for_autonamed_policy(fake):
    fake.score = 0.2
    pol = doc({"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"})
    run(policies.iam_grant_matches_stated_purpose, "aws:iam/policy:Policy", {"name": "read-metrics-3451220", "policy": pol}, name="read-metrics")
    assert fake.calls[0][0]["policy_name"] == "read-metrics"
