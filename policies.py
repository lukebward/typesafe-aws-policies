"""Fifteen AWS good-usage policies. Exact checks stay in code; each policy asks TypeSafe one narrow judgment."""
import json
from collections.abc import Mapping
from typing import Callable, NamedTuple

from pulumi_policy import EnforcementLevel, Severity
from typesafe_sdk import Noul, NoulCriteria, Score

import judge

S3_BUCKET = "aws:s3/bucket:Bucket"
S3_BUCKET_POLICY = "aws:s3/bucketPolicy:BucketPolicy"
IAM_POLICIES = ("aws:iam/policy:Policy", "aws:iam/rolePolicy:RolePolicy")
IAM_ROLE = "aws:iam/role:Role"
IAM_USER = "aws:iam/user:User"
SG = "aws:ec2/securityGroup:SecurityGroup"
SG_RULE = "aws:ec2/securityGroupRule:SecurityGroupRule"
EC2_INSTANCE = "aws:ec2/instance:Instance"
RDS = ("aws:rds/instance:Instance", "aws:rds/cluster:Cluster")
LAMBDA = "aws:lambda/function:Function"
CONTROL_PLANE_PREFIXES = ("pulumi:", "pulumiservice:")
ENV_CONFIDENCE = 0.6


def _statements(doc):
    doc = json.loads(doc) if isinstance(doc, str) else judge.plain(doc)
    stmts = doc.get("Statement", [])
    return stmts if isinstance(stmts, list) else [stmts]


def _as_list(value):
    return [value] if isinstance(value, str) else list(value or [])


def _tags(args):
    tags = args.props.get("tags")
    return tags if isinstance(tags, Mapping) else None


def _tag(tags, key):
    return next(((k, v) for k, v in tags.items() if k.lower() == key), (None, None))


def _is_prod(tags):
    label, confidence = judge.env_class(tags)
    return label == "production" and confidence >= ENV_CONFIDENCE


def s3_bucket_policy_not_public(args, report):
    """S3 bucket policies must not grant access to anonymous users or to every AWS principal."""
    if args.resource_type != S3_BUCKET_POLICY:
        return
    p = judge.noul(
        {"statements": _statements(args.props["policy"])},
        "Does any Allow statement in `statements` grant access to anonymous users or to every AWS principal without a condition that limits who can use it?",
        NoulCriteria(
            true="Principal is * or {AWS: *} with no Condition, or with a Condition that still lets anyone through",
            false="Every Allow statement names specific accounts, roles, or services, or restricts access with a Condition such as aws:SourceVpce, aws:PrincipalOrgID, or aws:SourceArn",
        ),
    )
    if p >= judge.HIGH:
        report(f"bucket policy grants public access (p={p:.2f})")


def s3_sensitive_bucket_encrypted(args, report):
    """S3 buckets that appear to hold sensitive data must configure server-side encryption."""
    if args.resource_type != S3_BUCKET or args.props.get("serverSideEncryptionConfiguration"):
        return
    p = judge.noul(
        {"bucket_name": args.props.get("bucket") or args.name, "tags": _tags(args) or {}},
        "Do `bucket_name` or `tags` suggest the bucket stores sensitive data such as personal data, customer records, credentials, backups, financial records, or audit logs?",
    )
    if p >= judge.DEFAULT:
        report(f"bucket looks sensitive and has no server-side encryption configured (p={p:.2f})")


def iam_no_admin_equivalent(args, report):
    """IAM policies must not grant administrator-equivalent access, directly or through an escalation path."""
    if args.resource_type not in IAM_POLICIES:
        return
    p = judge.noul(
        {"statements": _statements(args.props["policy"])},
        "Do the permissions in `statements` let the holder gain full control of the AWS account, either directly or by chaining the allowed actions?",
        NoulCriteria(
            true="Allows all actions, allows iam:* or an equivalent, or allows a known escalation path such as iam:PassRole together with creating or running compute (Lambda, EC2, ECS, Glue, CloudFormation), creating access keys or login profiles for other identities, attaching or putting IAM policies, or creating and setting IAM policy versions",
            false="Permissions stay within specific services and cannot be combined to obtain broader IAM access",
        ),
    )
    if p >= judge.HIGH:
        report(f"policy is administrator-equivalent or contains a privilege escalation path (p={p:.2f})")


def iam_mutating_actions_scoped(args, report):
    """IAM policies that allow actions which create, change, or delete things must name specific resources, not *."""
    if args.resource_type not in IAM_POLICIES:
        return
    actions = []
    for stmt in _statements(args.props["policy"]):
        if stmt.get("Effect") == "Allow" and "*" in _as_list(stmt.get("Resource")):
            actions.extend(_as_list(stmt.get("Action")))
    if not actions:
        return
    p = judge.noul(
        {"actions": actions},
        "Do any of the actions in `actions` create, modify, delete, or change permissions on AWS resources rather than only read or list them?",
        NoulCriteria(
            true="At least one action creates, updates, deletes, terminates, puts, attaches, or otherwise changes a resource or permission, including service wildcards such as s3:* or ec2:*",
            false="Every action is read-only, such as Get*, List*, Describe*, or a read-only wildcard like ec2:Describe*",
        ),
    )
    if p >= judge.DEFAULT:
        report(f"mutating actions {actions} are allowed on Resource * (p={p:.2f})")


def iam_trust_policy_restricted(args, report):
    """IAM role trust policies must not let every principal, or another account without a condition, assume the role."""
    if args.resource_type != IAM_ROLE:
        return
    doc = args.props.get("assumeRolePolicy")
    if not doc:
        return
    p = judge.noul(
        {"statements": _statements(doc)},
        "Does any statement in `statements` let every AWS principal, or a principal from a different AWS account with no limiting condition, assume this role?",
        NoulCriteria(
            true="Principal is * or {AWS: *}, or an AWS account or role from another account with no Condition such as sts:ExternalId, aws:PrincipalOrgID, or aws:SourceArn",
            false="Principals are AWS services, identity providers with audience conditions, or accounts restricted by a Condition",
        ),
    )
    if p >= judge.HIGH:
        report(f"trust policy lets untrusted principals assume the role (p={p:.2f})")


def iam_no_service_users(args, report):
    """IAM users are for people. Machine and service identities should use roles."""
    if args.resource_type != IAM_USER:
        return
    user_name = args.props.get("name") or args.name
    p = judge.noul(
        {"user_name": user_name},
        "Does `user_name` identify a machine, service, application, pipeline, or bot rather than a person?",
        NoulCriteria(
            true="Names like ci-deploy, app-svc, terraform, backup-bot, jenkins, github-actions, or a product name",
            false="A person's name, initials, or handle such as jane.doe or jdoe",
        ),
    )
    if p >= judge.DEFAULT:
        report(f"IAM user '{user_name}' looks like a service identity; use a role instead (p={p:.2f})")


def _public_ingress_rules(args):
    if args.resource_type == SG:
        rules = args.props.get("ingress") or []
    elif args.resource_type == SG_RULE and args.props.get("type") == "ingress":
        rules = [args.props]
    else:
        return []
    rules = [judge.plain(r) for r in rules]
    return [r for r in rules if any(judge.is_public_cidr(c) for c in (r.get("cidrBlocks") or []) + (r.get("ipv6CidrBlocks") or []))]


def sg_no_public_admin_ports(args, report):
    """Security groups must not expose remote administration or database ports to the public internet."""
    rules = _public_ingress_rules(args)
    if not rules:
        return
    state = {"rules": [{k: r.get(k) for k in ("fromPort", "toPort", "protocol", "description")} for r in rules]}
    questions = {
        f"rule_{i}": Noul(
            instructions=f"Based on its port range and protocol, does `rules[{i}]` expose a remote administration service (SSH, RDP, WinRM, VNC, Telnet) or a database or cache engine (PostgreSQL, MySQL, SQL Server, Oracle, Redis, MongoDB, Elasticsearch, Memcached)? A protocol of -1 or a port range that includes such ports counts as yes.",
        )
        for i in range(len(rules))
    }
    answers = judge.ask(state, questions).nouls
    for i, r in enumerate(rules):
        p = answers[f"rule_{i}"].noul
        if p >= judge.DEFAULT:
            report(f"ingress {r.get('protocol')} {r.get('fromPort')}-{r.get('toPort')} is open to the internet and looks like an admin or database port (p={p:.2f})")


def sg_description_meaningful(args, report):
    """Security group descriptions must explain what the group is for and what traffic it allows."""
    if args.resource_type != SG:
        return
    description = args.props.get("description") or ""
    score = judge.ask(
        {"description": description},
        {
            "quality": Score(
                instructions="How well does `description` explain what this security group is for and what traffic it allows?",
                criteria=[
                    "Empty, a placeholder, or a default such as 'Managed by Pulumi', 'sg', or 'security group'",
                    "Names a component but not its purpose or traffic, such as 'web' or 'db sg'",
                    "States the component and the traffic it allows, such as 'Allows HTTPS from the ALB to the API service'",
                ],
            )
        },
    ).scores["quality"].score
    if score < 1.0:
        report(f"description '{description}' does not explain the group's purpose (score={score:.1f} of 2)")


def ec2_no_public_ip_in_prod(args, report):
    """Production EC2 instances must not request a public IP address."""
    if args.resource_type != EC2_INSTANCE or args.props.get("associatePublicIpAddress") is not True:
        return
    if _is_prod(_tags(args) or {}):
        report("production instance requests a public IP address")


def rds_prod_not_public(args, report):
    """Production databases must not be publicly accessible."""
    if args.resource_type not in RDS or args.props.get("publiclyAccessible") is not True:
        return
    if _is_prod(_tags(args) or {}):
        report("production database is publicly accessible")


def rds_prod_backups_and_protection(args, report):
    """Production databases must keep at least 7 days of backups and enable deletion protection."""
    if args.resource_type not in RDS or not _is_prod(_tags(args) or {}):
        return
    retention = args.props.get("backupRetentionPeriod", 1)
    if retention < 7:
        report(f"backupRetentionPeriod is {retention}; production needs at least 7")
    if not args.props.get("deletionProtection"):
        report("deletionProtection is not enabled on a production database")


def lambda_no_plaintext_secrets(args, report):
    """Lambda environment variables must not carry credentials in plaintext."""
    if args.resource_type != LAMBDA:
        return
    env = args.props.get("environment")
    variables = env.get("variables") if isinstance(env, Mapping) else None
    if not variables:
        return
    names = list(variables)
    state = {"variables": [{"name": n, "value_shape": judge.value_shape(str(variables[n]))} for n in names]}
    questions = {
        f"var_{i}": Noul(
            instructions=f"Given its name and the shape of its value, is `variables[{i}]` a credential, API key, token, or password stored in plaintext?",
            criteria=NoulCriteria(
                true="The name suggests a secret (password, secret, token, key, credential, auth) and the value shape is consistent with a literal secret: long, mixed character classes, or a known credential prefix",
                false="The name is not secret-like, or the value shape looks like a URL, an ARN, a short setting such as 'info' or 'true', or a reference to a secret store",
            ),
        )
        for i in range(len(names))
    }
    answers = judge.ask(state, questions).nouls
    for i, n in enumerate(names):
        p = answers[f"var_{i}"].noul
        if p >= judge.HIGH:
            report(f"environment variable {n} looks like a plaintext secret (p={p:.2f})")


def tags_owner_is_real(args, report):
    """The owner tag must name a real team or person, not a placeholder."""
    if args.resource_type.startswith(CONTROL_PLANE_PREFIXES):
        return
    tags = _tags(args)
    if tags is None:
        return
    key, owner = _tag(tags, "owner")
    if key is None:
        return
    p = judge.noul(
        {"owner": owner},
        "Is `owner` a placeholder or filler value rather than the name of a real team or person?",
        NoulCriteria(
            true="todo, tbd, tba, n/a, none, test, asdf, me, someone, unknown, a single character, or a generic word such as admin or user",
            false="A team name, a person's name, an email address, a handle, or a group alias",
        ),
    )
    if p >= judge.DEFAULT:
        report(f"owner tag '{owner}' looks like a placeholder (p={p:.2f})")


def tags_env_recognized(args, report):
    """The environment tag must map to a recognized environment."""
    if args.resource_type.startswith(CONTROL_PLANE_PREFIXES):
        return
    tags = _tags(args)
    if tags is None or judge.env_tag(tags) is None:
        return
    label, confidence = judge.env_class(tags)
    if label == "unknown" or confidence < ENV_CONFIDENCE:
        _, value = judge.env_tag(tags)
        report(f"environment tag '{value}' is not a recognized environment (read as {label}, confidence={confidence:.2f})")


def resource_name_descriptive(args, report):
    """Resource names must describe the resource, not be placeholders."""
    if args.resource_type.startswith("pulumi:"):
        return
    p = judge.noul(
        {"resource_type": args.resource_type, "name": args.name},
        "Is `name` a placeholder, test, or throwaway name rather than a name that describes what this resource is for?",
        NoulCriteria(
            true="test, foo, bar, tmp, temp, asdf, my-bucket, bucket1, resource, new, untitled, or a generic word with a number suffix",
            false="Describes the workload, purpose, or component, such as api-logs, payments-db, or vpc-main",
        ),
    )
    if p >= judge.DEFAULT:
        report(f"resource name '{args.name}' looks like a placeholder (p={p:.2f})")


class Rule(NamedTuple):
    name: str
    validate: Callable
    enforcement: EnforcementLevel
    severity: Severity


MANDATORY, ADVISORY = EnforcementLevel.MANDATORY, EnforcementLevel.ADVISORY

POLICIES = [
    Rule("s3-bucket-policy-not-public", s3_bucket_policy_not_public, MANDATORY, Severity.CRITICAL),
    Rule("s3-sensitive-bucket-encrypted", s3_sensitive_bucket_encrypted, MANDATORY, Severity.HIGH),
    Rule("iam-no-admin-equivalent", iam_no_admin_equivalent, MANDATORY, Severity.CRITICAL),
    Rule("iam-mutating-actions-scoped", iam_mutating_actions_scoped, MANDATORY, Severity.HIGH),
    Rule("iam-trust-policy-restricted", iam_trust_policy_restricted, MANDATORY, Severity.CRITICAL),
    Rule("iam-no-service-users", iam_no_service_users, ADVISORY, Severity.MEDIUM),
    Rule("sg-no-public-admin-ports", sg_no_public_admin_ports, MANDATORY, Severity.CRITICAL),
    Rule("sg-description-meaningful", sg_description_meaningful, ADVISORY, Severity.LOW),
    Rule("ec2-no-public-ip-in-prod", ec2_no_public_ip_in_prod, MANDATORY, Severity.HIGH),
    Rule("rds-prod-not-public", rds_prod_not_public, MANDATORY, Severity.CRITICAL),
    Rule("rds-prod-backups-and-protection", rds_prod_backups_and_protection, MANDATORY, Severity.HIGH),
    Rule("lambda-no-plaintext-secrets", lambda_no_plaintext_secrets, MANDATORY, Severity.HIGH),
    Rule("tags-owner-is-real", tags_owner_is_real, ADVISORY, Severity.MEDIUM),
    Rule("tags-env-recognized", tags_env_recognized, ADVISORY, Severity.LOW),
    Rule("resource-name-descriptive", resource_name_descriptive, ADVISORY, Severity.LOW),
]
