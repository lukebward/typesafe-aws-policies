"""Live tests against the TypeSafe API. Skipped unless TYPESAFE_API_KEY is set.

Run: TYPESAFE_API_KEY=... venv/bin/python -m pytest -q test_live.py -rs
Each case is (policy, resource_type, props, expect_violation). Probabilities print with -s.
"""
import json
import os
from types import MappingProxyType, SimpleNamespace

import pytest

import judge
import policies

pytestmark = pytest.mark.skipif(not os.environ.get("TYPESAFE_API_KEY"), reason="TYPESAFE_API_KEY not set")


def doc(*stmts):
    return json.dumps({"Version": "2012-10-17", "Statement": list(stmts)})


CASES = [
    ("s3-bucket-policy-not-public", "aws:s3/bucketPolicy:BucketPolicy",
     {"policy": doc({"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"})}, True),
    ("s3-bucket-policy-not-public", "aws:s3/bucketPolicy:BucketPolicy",
     {"policy": doc({"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:role/reader"}, "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"})}, False),
    ("s3-bucket-policy-not-public", "aws:s3/bucketPolicy:BucketPolicy",
     {"policy": doc({"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*",
                     "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}}})}, False),
    ("s3-sensitive-bucket-encrypted", "aws:s3/bucket:Bucket", {"bucket": "customer-pii-exports"}, True),
    ("s3-sensitive-bucket-encrypted", "aws:s3/bucket:Bucket", {"bucket": "static-website-assets"}, False),
    ("iam-no-admin-equivalent", "aws:iam/policy:Policy",
     {"policy": doc({"Effect": "Allow", "Action": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"], "Resource": "*"})}, True),
    ("iam-no-admin-equivalent", "aws:iam/policy:Policy",
     {"policy": doc({"Effect": "Allow", "Action": ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"], "Resource": "*"})}, True),
    ("iam-no-admin-equivalent", "aws:iam/policy:Policy",
     {"policy": doc({"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"], "Resource": "arn:aws:s3:::b/*"})}, False),
    ("iam-mutating-actions-scoped", "aws:iam/policy:Policy",
     {"policy": doc({"Effect": "Allow", "Action": ["ec2:TerminateInstances"], "Resource": "*"})}, True),
    ("iam-mutating-actions-scoped", "aws:iam/policy:Policy",
     {"policy": doc({"Effect": "Allow", "Action": ["ec2:Describe*", "s3:ListAllMyBuckets"], "Resource": "*"})}, False),
    ("iam-trust-policy-restricted", "aws:iam/role:Role",
     {"assumeRolePolicy": doc({"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"})}, True),
    ("iam-trust-policy-restricted", "aws:iam/role:Role",
     {"assumeRolePolicy": doc({"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"})}, False),
    ("iam-no-service-users", "aws:iam/user:User", {"name": "ci-deploy-bot"}, True),
    ("iam-no-service-users", "aws:iam/user:User", {"name": "jane.doe"}, False),
    ("sg-no-public-admin-ports", "aws:ec2/securityGroup:SecurityGroup",
     {"ingress": [{"fromPort": 22, "toPort": 22, "protocol": "tcp", "cidrBlocks": ["0.0.0.0/0"]}]}, True),
    ("sg-no-public-admin-ports", "aws:ec2/securityGroup:SecurityGroup",
     {"ingress": [{"fromPort": 443, "toPort": 443, "protocol": "tcp", "cidrBlocks": ["0.0.0.0/0"]}]}, False),
    ("sg-description-meaningful", "aws:ec2/securityGroup:SecurityGroup", {"description": "Managed by Pulumi"}, True),
    ("sg-description-meaningful", "aws:ec2/securityGroup:SecurityGroup", {"description": "Allows HTTPS from the ALB to the API service"}, False),
    ("ec2-no-public-ip-in-prod", "aws:ec2/instance:Instance", {"associatePublicIpAddress": True, "tags": {"env": "prd"}}, True),
    ("ec2-no-public-ip-in-prod", "aws:ec2/instance:Instance", {"associatePublicIpAddress": True, "tags": {"env": "dev"}}, False),
    ("rds-prod-not-public", "aws:rds/instance:Instance", {"publiclyAccessible": True, "tags": {"Environment": "production"}}, True),
    ("rds-prod-backups-and-protection", "aws:rds/instance:Instance", {"backupRetentionPeriod": 1, "deletionProtection": False, "tags": {"env": "prod"}}, True),
    ("rds-prod-backups-and-protection", "aws:rds/instance:Instance", {"backupRetentionPeriod": 1, "deletionProtection": False, "tags": {"env": "sandbox"}}, False),
    ("lambda-no-plaintext-secrets", "aws:lambda/function:Function",
     {"environment": {"variables": {"STRIPE_SECRET_KEY": "sk-live-4eC39HqLyjWDarjtT1zdp7dc"}}}, True),
    ("lambda-no-plaintext-secrets", "aws:lambda/function:Function",
     {"environment": {"variables": {"LOG_LEVEL": "info", "API_URL": "https://api.example.com"}}}, False),
    ("tags-owner-is-real", "aws:s3/bucket:Bucket", {"tags": {"owner": "todo"}}, True),
    ("tags-owner-is-real", "aws:s3/bucket:Bucket", {"tags": {"owner": "platform-team"}}, False),
    ("tags-env-recognized", "aws:s3/bucket:Bucket", {"tags": {"env": "banana"}}, True),
    ("tags-env-recognized", "aws:s3/bucket:Bucket", {"tags": {"env": "staging"}}, False),
    ("resource-name-descriptive", "aws:s3/bucket:Bucket", {"name": "test123"}, True),
    ("resource-name-descriptive", "aws:s3/bucket:Bucket", {"name": "payments-audit-logs"}, False),
]

BY_NAME = {rule.name: rule.validate for rule in policies.POLICIES}


@pytest.mark.parametrize("policy_name,resource_type,props,expect_violation", CASES,
                         ids=[f"{c[0]}:{'bad' if c[3] else 'good'}:{i}" for i, c in enumerate(CASES)])
def test_policy_against_live_model(policy_name, resource_type, props, expect_violation):
    judge._cache.clear()
    out = []
    name = props.pop("name", "res")
    args = SimpleNamespace(resource_type=resource_type, props=MappingProxyType(props), name=name, urn=f"urn::{name}")
    BY_NAME[policy_name](args, lambda m, urn=None: out.append(m))
    print(f"\n{policy_name}: {out or 'no violation'}")
    assert bool(out) == expect_violation, out
