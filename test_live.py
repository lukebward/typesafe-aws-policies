"""Live tests against the TypeSafe API. Skipped unless TYPESAFE_API_KEY is set.

Run: TYPESAFE_API_KEY=... venv/bin/python -m pytest -q test_live.py -s
Each case is (policy, resource_type, props, expect_violation). Messages print with -s.
"""
import json
import os
from types import MappingProxyType, SimpleNamespace

import pytest

import judge
import policies

judge.load_dotenv()
pytestmark = pytest.mark.skipif(not os.environ.get("TYPESAFE_API_KEY"), reason="TYPESAFE_API_KEY not set")


def doc(*stmts):
    return json.dumps({"Version": "2012-10-17", "Statement": list(stmts)})


ORG = {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}}
TLS = {"Bool": {"aws:SecureTransport": "true"}}
GITHUB = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"

CASES = [
    # 1 resource-policy-not-open: the gray zone only, the wildcard-without-condition case is code
    ("resource-policy-not-open", "aws:s3/bucketPolicy:BucketPolicy",
     {"policy": doc({"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*", "Condition": TLS})}, True),
    ("resource-policy-not-open", "aws:s3/bucketPolicy:BucketPolicy",
     {"policy": doc({"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*", "Condition": ORG})}, False),
    ("resource-policy-not-open", "aws:kms/key:Key",
     {"policy": doc({"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "kms:Decrypt", "Resource": "*",
                     "Condition": {"StringEquals": {"kms:CallerAccount": "123456789012", "kms:ViaService": "s3.us-west-2.amazonaws.com"}}})}, False),
    # 2 sensitive-data-store-encrypted
    ("sensitive-data-store-encrypted", "aws:dynamodb/table:Table", {"name": "patient-records", "tags": {"team": "clinical"}}, True),
    ("sensitive-data-store-encrypted", "aws:rds/instance:Instance", {"identifier": "billing-ledger", "storageEncrypted": False}, True),
    ("sensitive-data-store-encrypted", "aws:ebs/volume:Volume", {"encrypted": False, "tags": {"purpose": "ci-build-cache"}, "name": "ci-scratch"}, False),
    ("sensitive-data-store-encrypted", "aws:s3/bucket:Bucket", {"bucket": "marketing-site-static-assets"}, False),
    # 3 prod-or-sensitive-store-protected
    ("prod-or-sensitive-store-protected", "aws:rds/instance:Instance",
     {"identifier": "orders", "backupRetentionPeriod": 1, "deletionProtection": False, "multiAz": False, "tags": {"env": "prd-us-east"}}, True),
    ("prod-or-sensitive-store-protected", "aws:rds/instance:Instance",
     {"identifier": "orders", "backupRetentionPeriod": 1, "deletionProtection": False, "multiAz": False, "tags": {"env": "sandbox"}}, False),
    ("prod-or-sensitive-store-protected", "aws:s3/bucket:Bucket", {"bucket": "customer-pii-exports"}, True),
    ("prod-or-sensitive-store-protected", "aws:s3/bucket:Bucket", {"bucket": "ci-build-cache", "tags": {"env": "dev"}}, False),
    # 4 iam-no-admin-equivalent
    ("iam-no-admin-equivalent", "aws:iam/policy:Policy",
     {"policy": doc({"Effect": "Allow", "Action": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"], "Resource": "*"})}, True),
    ("iam-no-admin-equivalent", "aws:iam/policy:Policy",
     {"policy": doc({"Effect": "Allow", "Action": ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"], "Resource": "*"})}, True),
    ("iam-no-admin-equivalent", "aws:iam/policy:Policy",
     {"policy": doc({"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"], "Resource": "arn:aws:s3:::b/*"})}, False),
    ("iam-no-admin-equivalent", "aws:iam/policy:Policy",
     {"policy": doc({"Effect": "Allow", "Action": ["iam:PassRole", "batch:*"], "Resource": "*"})}, True),
    ("iam-no-admin-equivalent", "aws:iam/policy:Policy",
     {"policy": doc({"Effect": "Allow", "Action": ["iam:PassRole", "route53:*"], "Resource": "*"})}, False),
    # 5 iam-grant-matches-stated-purpose
    ("iam-grant-matches-stated-purpose", "aws:iam/policy:Policy",
     {"name": "read-metrics", "description": "Read CloudWatch metrics for the ops dashboard",
      "policy": doc({"Effect": "Allow", "Action": ["cloudwatch:*", "ec2:*"], "Resource": "*"})}, True),
    ("iam-grant-matches-stated-purpose", "aws:iam/policy:Policy",
     {"name": "read-metrics", "description": "Read CloudWatch metrics for the ops dashboard",
      "policy": doc({"Effect": "Allow", "Action": ["cloudwatch:GetMetricData", "cloudwatch:ListMetrics"], "Resource": "*"})}, False),
    # 6 iam-trust-policy-restricted
    ("iam-trust-policy-restricted", "aws:iam/role:Role",
     {"assumeRolePolicy": doc({"Effect": "Allow", "Principal": {"Federated": GITHUB}, "Action": "sts:AssumeRoleWithWebIdentity",
                               "Condition": {"StringLike": {"token.actions.githubusercontent.com:sub": "repo:acme/*:*"}}})}, True),
    ("iam-trust-policy-restricted", "aws:iam/role:Role",
     {"assumeRolePolicy": doc({"Effect": "Allow", "Principal": {"Federated": GITHUB}, "Action": "sts:AssumeRoleWithWebIdentity",
                               "Condition": {"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                                                              "token.actions.githubusercontent.com:sub": "repo:acme/shop:ref:refs/heads/main"}}})}, False),
    ("iam-trust-policy-restricted", "aws:iam/role:Role",
     {"assumeRolePolicy": doc({"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999999999999:root"}, "Action": "sts:AssumeRole",
                               "Condition": {"Bool": {"aws:SecureTransport": "true"}}})}, True),
    ("iam-trust-policy-restricted", "aws:iam/role:Role",
     {"assumeRolePolicy": doc({"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999999999999:root"}, "Action": "sts:AssumeRole",
                               "Condition": {"ArnLike": {"aws:PrincipalArn": "arn:aws:iam::999999999999:role/*"}}})}, True),
    ("iam-trust-policy-restricted", "aws:iam/role:Role",
     {"assumeRolePolicy": doc({"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999999999999:root"}, "Action": "sts:AssumeRole",
                               "Condition": {"StringEquals": {"sts:ExternalId": "vendor-42"}}})}, False),
    # 7 iam-no-service-users
    ("iam-no-service-users", "aws:iam/user:User", {"name": "ci-deploy-bot"}, True),
    ("iam-no-service-users", "aws:iam/user:User", {"name": "jane.doe"}, False),
    # 8 sg-rule-matches-description
    ("sg-rule-matches-description", "aws:ec2/securityGroup:SecurityGroup",
     {"ingress": [{"fromPort": 0, "toPort": 65535, "protocol": "tcp", "cidrBlocks": ["0.0.0.0/0"], "description": "HTTPS from the ALB"}]}, True),
    ("sg-rule-matches-description", "aws:ec2/securityGroup:SecurityGroup",
     {"ingress": [{"fromPort": 443, "toPort": 443, "protocol": "tcp", "cidrBlocks": ["0.0.0.0/0"], "description": "Public HTTPS to the web tier"}]}, False),
    ("sg-rule-matches-description", "aws:ec2/securityGroup:SecurityGroup",
     {"ingress": [{"fromPort": 0, "toPort": 0, "protocol": "-1", "cidrBlocks": ["10.0.0.0/8"], "description": "All traffic inside the VPC"}]}, False),
    # 9 sg-description-meaningful
    ("sg-description-meaningful", "aws:ec2/securityGroup:SecurityGroup", {"description": "Managed by Pulumi"}, True),
    ("sg-description-meaningful", "aws:ec2/securityGroup:SecurityGroup", {"description": "Allows HTTPS from the ALB to the API service"}, False),
    # 10 internal-resource-not-public
    ("internal-resource-not-public", "aws:ec2/instance:Instance", {"associatePublicIpAddress": True, "tags": {"role": "admin-console"}, "name": "admin-console"}, True),
    ("internal-resource-not-public", "aws:lb/loadBalancer:LoadBalancer", {"name": "public-web-alb"}, False),
    ("internal-resource-not-public", "aws:lambda/functionUrl:FunctionUrl", {"authorizationType": "NONE", "functionName": "internal-report-generator"}, True),
    # 11 log-and-temp-buckets-have-lifecycle
    ("log-and-temp-buckets-have-lifecycle", "aws:s3/bucket:Bucket", {"bucket": "alb-access-logs"}, True),
    ("log-and-temp-buckets-have-lifecycle", "aws:s3/bucket:Bucket", {"bucket": "customer-uploads"}, False),
    # 12 no-plaintext-secrets-in-env
    ("no-plaintext-secrets-in-env", "aws:lambda/function:Function",
     {"environment": {"variables": {"STRIPE_SECRET_KEY": "sk-live-4eC39HqLyjWDarjtT1zdp7dc"}}}, True),
    ("no-plaintext-secrets-in-env", "aws:ecs/taskDefinition:TaskDefinition",
     {"containerDefinitions": json.dumps([{"name": "api", "environment": [{"name": "DB_PASSWORD", "value": "Tr0ub4dor&3xyz"}]}])}, True),
    ("no-plaintext-secrets-in-env", "aws:lambda/function:Function",
     {"environment": {"variables": {"LOG_LEVEL": "info", "API_URL": "https://api.example.com", "DB_SECRET_ARN": "arn:aws:secretsmanager:us-west-2:123:secret:db"}}}, False),
    # 13 tags-meaningful
    ("tags-meaningful", "aws:s3/bucket:Bucket", {"tags": {"owner": "todo", "env": "banana", "cost-center": "n/a"}}, True),
    ("tags-meaningful", "aws:s3/bucket:Bucket", {"tags": {"owner": "platform-team", "env": "staging", "cost-center": "CC-4410"}}, False),
    # 14 name-consistent-with-config
    ("name-consistent-with-config", "aws:rds/instance:Instance", {"identifier": "prod-orders-db", "tags": {"env": "dev"}}, True),
    ("name-consistent-with-config", "aws:rds/instance:Instance", {"identifier": "orders-db", "tags": {"env": "dev"}}, False),
    # 15 sqs-work-queue-has-dlq
    ("sqs-work-queue-has-dlq", "aws:sqs/queue:Queue", {"name": "order-processing"}, True),
    ("sqs-work-queue-has-dlq", "aws:sqs/queue:Queue", {"name": "order-processing-dlq"}, False),
]

BY_NAME = {rule.name: rule.validate for rule in policies.POLICIES}


@pytest.mark.parametrize("policy_name,resource_type,props,expect_violation", CASES,
                         ids=[f"{c[0]}:{'bad' if c[3] else 'good'}:{i}" for i, c in enumerate(CASES)])
def test_policy_against_live_model(policy_name, resource_type, props, expect_violation):
    judge._cache.clear()
    out = []
    name = props.get("name") or props.get("bucket") or props.get("identifier") or "res"
    args = SimpleNamespace(resource_type=resource_type, props=MappingProxyType(props), name=name, urn="urn::res")
    BY_NAME[policy_name](args, lambda m, urn=None: out.append(m))
    print(f"\n{policy_name}: {out or 'no violation'}")
    assert bool(out) == expect_violation, out
