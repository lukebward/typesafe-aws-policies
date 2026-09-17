"""Fifteen AWS good-usage policies.

Code decides every case it can decide exactly. The model only gets the gray zone: intent, purpose,
consistency between fields, and whether a condition or description means what it claims.
"""
import json
from collections.abc import Mapping
from typing import Callable, NamedTuple

from pulumi_policy import EnforcementLevel, Severity
from typesafe_sdk import Choice, Noul, NoulCriteria, Score

import judge

S3_BUCKET = "aws:s3/bucket:Bucket"
RDS_INSTANCE, RDS_CLUSTER = "aws:rds/instance:Instance", "aws:rds/cluster:Cluster"
DYNAMODB_TABLE = "aws:dynamodb/table:Table"
IAM_POLICY_TYPES = ("aws:iam/policy:Policy", "aws:iam/rolePolicy:RolePolicy", "aws:iam/userPolicy:UserPolicy", "aws:iam/groupPolicy:GroupPolicy")
IAM_ROLE, IAM_USER = "aws:iam/role:Role", "aws:iam/user:User"
SG, SG_RULE, VPC_INGRESS_RULE = "aws:ec2/securityGroup:SecurityGroup", "aws:ec2/securityGroupRule:SecurityGroupRule", "aws:vpc/securityGroupIngressRule:SecurityGroupIngressRule"
LAMBDA, ECS_TASK, CODEBUILD = "aws:lambda/function:Function", "aws:ecs/taskDefinition:TaskDefinition", "aws:codebuild/project:Project"
SQS_QUEUE = "aws:sqs/queue:Queue"
CONTROL_PLANE_PREFIXES = ("pulumi:", "pulumiservice:")
ENV_CONFIDENCE = 0.6
COST_CENTER_KEYS = ("cost-center", "costcenter", "cost_center")

SENSITIVE_QUESTION = "Do `name`, `tags`, or `description` suggest this store holds sensitive data such as personal data, customer records, health or financial records, credentials, backups, or audit logs?"
SENSITIVE_CRITERIA = NoulCriteria(
    true="Names or tags mention customers, users, PII, patients, payments, finance, secrets, credentials, backups, audit, compliance, or a regulated data class",
    false="Names or tags describe public assets, static sites, scratch or test data, caches, or build artifacts",
)


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


def _identity(args):
    p = args.props
    name = p.get("name") or p.get("bucket") or p.get("identifier") or p.get("functionName") or args.name
    return {"resource_type": args.resource_type, "name": name, "tags": judge.plain(_tags(args) or {}), "description": p.get("description")}


def _wildcard_principal(stmt):
    principal = stmt.get("Principal")
    if principal == "*":
        return True
    return isinstance(principal, Mapping) and "*" in _as_list(principal.get("AWS"))


def _percent(p):
    return f"(p={p:.2f})"


# 1
RESOURCE_POLICY_TYPES = ("aws:s3/bucketPolicy:BucketPolicy", "aws:kms/key:Key", "aws:sqs/queuePolicy:QueuePolicy", "aws:sns/topicPolicy:TopicPolicy", "aws:secretsmanager/secretPolicy:SecretPolicy")


def resource_policy_not_open(args, report):
    """Resource policies on S3, KMS, SQS, SNS, and Secrets Manager must not let anonymous or arbitrary principals in."""
    if args.resource_type not in RESOURCE_POLICY_TYPES or not args.props.get("policy"):
        return
    gray = []
    for stmt in _statements(args.props["policy"]):
        if stmt.get("Effect") != "Allow" or not _wildcard_principal(stmt):
            continue
        if not stmt.get("Condition"):
            report("statement allows every principal and has no Condition")
        else:
            gray.append(stmt)
    if not gray:
        return
    questions = {
        f"stmt_{i}": Noul(
            instructions=f"Does `statements[{i}]` still allow callers from outside the owning account or organization despite its Condition?",
            criteria=NoulCriteria(
                true="The Condition only constrains how the call is made, such as aws:SecureTransport, request headers, user agent, encryption settings, or broad IP ranges, and not who makes it",
                false="The Condition restricts the caller to an organization, account, VPC endpoint, or source resource, such as aws:PrincipalOrgID, aws:PrincipalAccount, aws:SourceVpce, aws:SourceArn, aws:SourceAccount, or kms:CallerAccount",
            ),
        )
        for i in range(len(gray))
    }
    answers = judge.ask({"statements": gray}, questions).nouls
    for i in range(len(gray)):
        p = answers[f"stmt_{i}"].noul
        if p >= judge.DEFAULT:
            report(f"statement allows every principal and its Condition does not limit who can call {_percent(p)}")


# 2
ENCRYPTED = {
    S3_BUCKET: lambda p: bool(p.get("serverSideEncryptionConfiguration")),
    RDS_INSTANCE: lambda p: p.get("storageEncrypted") is True,
    RDS_CLUSTER: lambda p: p.get("storageEncrypted") is True,
    DYNAMODB_TABLE: lambda p: bool((p.get("serverSideEncryption") or {}).get("enabled")),
    "aws:ebs/volume:Volume": lambda p: p.get("encrypted") is True,
    "aws:efs/fileSystem:FileSystem": lambda p: p.get("encrypted") is True,
}


def sensitive_data_store_encrypted(args, report):
    """Data stores whose name, tags, or description suggest sensitive data must encrypt data at rest."""
    encrypted = ENCRYPTED.get(args.resource_type)
    if encrypted is None or encrypted(args.props):
        return
    p = judge.noul(_identity(args), SENSITIVE_QUESTION, SENSITIVE_CRITERIA)
    if p >= judge.DEFAULT:
        report(f"store looks sensitive and is not encrypted at rest {_percent(p)}")


# 3
def _protection_gaps(args):
    p, t = args.props, args.resource_type
    gaps = []
    if t in (RDS_INSTANCE, RDS_CLUSTER):
        if p.get("backupRetentionPeriod", 1) < 7:
            gaps.append("backupRetentionPeriod is below 7 days")
        if not p.get("deletionProtection"):
            gaps.append("deletionProtection is disabled")
        if t == RDS_INSTANCE and not p.get("multiAz"):
            gaps.append("multiAz is disabled")
    elif t == S3_BUCKET and not (p.get("versioning") or {}).get("enabled"):
        gaps.append("versioning is disabled")
    elif t == DYNAMODB_TABLE and not (p.get("pointInTimeRecovery") or {}).get("enabled"):
        gaps.append("pointInTimeRecovery is disabled")
    return gaps


def prod_or_sensitive_store_protected(args, report):
    """Production or sensitive data stores must keep backups, versioning or point-in-time recovery, and deletion protection."""
    if args.resource_type not in (RDS_INSTANCE, RDS_CLUSTER, S3_BUCKET, DYNAMODB_TABLE):
        return
    gaps = _protection_gaps(args)
    if not gaps:
        return
    state = _identity(args)
    questions = {"sensitive": Noul(instructions=SENSITIVE_QUESTION, criteria=SENSITIVE_CRITERIA)}
    env = judge.env_tag(state["tags"])
    if env:
        state["env_tag"] = {"key": env[0], "value": env[1]}
        questions["env"] = Choice(instructions="Which environment does `env_tag.value` identify?", criteria=judge.ENV_CRITERIA)
    answers = judge.ask(state, questions)
    sensitive = answers.nouls["sensitive"].noul
    prod = False
    if env:
        a = answers.choices["env"]
        prod = a.choice == "production" and a.confidence >= ENV_CONFIDENCE
    if not prod and sensitive < judge.DEFAULT:
        return
    reason = "production store" if prod else f"sensitive store {_percent(sensitive)}"
    for gap in gaps:
        report(f"{reason}: {gap}")


# 4
def iam_no_admin_equivalent(args, report):
    """IAM policies must not grant administrator-equivalent access, directly or through an escalation path."""
    if args.resource_type not in IAM_POLICY_TYPES:
        return
    stmts = _statements(args.props["policy"])
    for stmt in stmts:
        if stmt.get("Effect") == "Allow" and any(a in ("*", "*:*") for a in _as_list(stmt.get("Action"))) and "*" in _as_list(stmt.get("Resource")):
            report("policy allows every action on every resource")
            return
    p = judge.noul(
        {"statements": stmts},
        "Do the permissions in `statements` let the holder gain full control of the AWS account by chaining the allowed actions?",
        NoulCriteria(
            true="Allows iam:* or an equivalent, or a known escalation path such as iam:PassRole together with creating or running compute (Lambda, EC2, ECS, Glue, CloudFormation), creating access keys or login profiles for other identities, attaching or putting IAM policies, or creating and setting IAM policy versions",
            false="Permissions stay within specific services and cannot be combined to obtain broader IAM access",
        ),
    )
    if p >= judge.HIGH:
        report(f"policy contains a privilege escalation path {_percent(p)}")


# 5
def iam_grant_matches_stated_purpose(args, report):
    """An IAM policy's grants must match the purpose stated by its name and description."""
    if args.resource_type not in IAM_POLICY_TYPES:
        return
    state = {
        "policy_name": args.props.get("name") or args.name,
        "description": args.props.get("description"),
        "tags": judge.plain(_tags(args) or {}),
        "statements": _statements(args.props["policy"]),
    }
    score = judge.ask(
        state,
        {
            "fit": Score(
                instructions="Compare the permissions in `statements` with the purpose stated by `policy_name` and `description`. How far does the grant go beyond that purpose?",
                criteria=[
                    "The grant matches the stated purpose: only the actions and resources that purpose needs",
                    "The grant is somewhat broader than the stated purpose, such as extra read access or a wildcard on the one service the purpose names",
                    "The grant is far broader than the stated purpose, such as full access to unrelated services, wildcard actions, or IAM permissions the purpose does not mention",
                ],
            )
        },
    ).scores["fit"].score
    if score >= 1.5:
        report(f"grant goes far beyond the stated purpose of '{state['policy_name']}' (score={score:.1f} of 2)")


# 6
def iam_trust_policy_restricted(args, report):
    """IAM role trust policies must pin who can assume the role, including federated subjects and cross-account conditions."""
    if args.resource_type != IAM_ROLE or not args.props.get("assumeRolePolicy"):
        return
    gray = []
    for stmt in _statements(args.props["assumeRolePolicy"]):
        if stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal")
        if _wildcard_principal(stmt) and not stmt.get("Condition"):
            report("trust policy lets every principal assume the role with no Condition")
        elif isinstance(principal, Mapping) and set(principal) == {"Service"}:
            continue
        else:
            gray.append(stmt)
    if not gray:
        return
    questions = {
        f"stmt_{i}": Noul(
            instructions=f"Does `statements[{i}]` let principals beyond one intended workload or identity assume this role?",
            criteria=NoulCriteria(
                true="An AWS account or role from another account with no sts:ExternalId or organization condition, a Federated OIDC or SAML principal whose conditions use wildcards that match many repositories, branches, or subjects (for example sub: repo:org/*:*), or conditions that do not constrain identity",
                false="A single account or role with an ExternalId or organization condition, or a Federated principal pinned to a specific audience and subject such as one repository and one branch",
            ),
        )
        for i in range(len(gray))
    }
    answers = judge.ask({"statements": gray}, questions).nouls
    for i in range(len(gray)):
        p = answers[f"stmt_{i}"].noul
        if p >= judge.DEFAULT:
            report(f"trust policy statement lets untrusted principals assume the role {_percent(p)}")


# 7
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
        report(f"IAM user '{user_name}' looks like a service identity; use a role instead {_percent(p)}")


# 8
def _ingress_rules(args):
    t, p = args.resource_type, args.props
    if t == SG:
        return [judge.plain(r) for r in p.get("ingress") or []]
    if t == SG_RULE and p.get("type") == "ingress":
        return [judge.plain(p)]
    if t == VPC_INGRESS_RULE:
        p = judge.plain(p)
        return [{
            "fromPort": p.get("fromPort"), "toPort": p.get("toPort"), "protocol": p.get("ipProtocol"),
            "cidrBlocks": [p["cidrIpv4"]] if p.get("cidrIpv4") else [],
            "ipv6CidrBlocks": [p["cidrIpv6"]] if p.get("cidrIpv6") else [],
            "description": p.get("description"),
        }]
    return []


def _sources(rule):
    return (rule.get("cidrBlocks") or []) + (rule.get("ipv6CidrBlocks") or [])


def _is_public(rule):
    return any(judge.is_public_cidr(c) for c in _sources(rule))


def _is_broad(rule):
    return str(rule.get("protocol")) == "-1" or (rule.get("fromPort") == 0 and rule.get("toPort") == 65535)


def _rule_label(rule):
    return f"{rule.get('protocol')} {rule.get('fromPort')}-{rule.get('toPort')} from {', '.join(_sources(rule)) or 'unspecified'}"


def sg_rule_matches_description(args, report):
    """Public or broad security group rules must carry a description that matches what the rule actually allows."""
    rules = [r for r in _ingress_rules(args) if _is_public(r) or _is_broad(r)]
    to_ask = []
    for r in rules:
        if r.get("description"):
            to_ask.append(r)
        else:
            report(f"ingress {_rule_label(r)} is public or broad and has no description")
    if not to_ask:
        return
    state = {"rules": [{k: r.get(k) for k in ("fromPort", "toPort", "protocol", "cidrBlocks", "ipv6CidrBlocks", "description")} for r in to_ask]}
    questions = {
        f"rule_{i}": Noul(
            instructions=f"Does `rules[{i}]` allow substantially more traffic than its `description` claims, in ports, protocol, or source?",
            criteria=NoulCriteria(
                true="The description names a narrower service, port, or source than the rule permits, for example 'HTTPS from the ALB' on a rule that opens all ports to 0.0.0.0/0",
                false="The description accurately covers the ports, protocol, and source the rule allows",
            ),
        )
        for i in range(len(to_ask))
    }
    answers = judge.ask(state, questions).nouls
    for i, r in enumerate(to_ask):
        p = answers[f"rule_{i}"].noul
        if p >= judge.DEFAULT:
            report(f"ingress {_rule_label(r)} allows more than its description '{r['description']}' claims {_percent(p)}")


# 9
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


# 10
PUBLIC = {
    "aws:ec2/instance:Instance": lambda p: p.get("associatePublicIpAddress") is True,
    RDS_INSTANCE: lambda p: p.get("publiclyAccessible") is True,
    RDS_CLUSTER: lambda p: p.get("publiclyAccessible") is True,
    "aws:lb/loadBalancer:LoadBalancer": lambda p: p.get("internal") is not True,
    "aws:alb/loadBalancer:LoadBalancer": lambda p: p.get("internal") is not True,
    "aws:lambda/functionUrl:FunctionUrl": lambda p: p.get("authorizationType") == "NONE",
}


def internal_resource_not_public(args, report):
    """Resources that look internal (admin, back office, worker, database) must not be reachable from the internet."""
    public = PUBLIC.get(args.resource_type)
    if public is None or not public(args.props):
        return
    identity = _identity(args)
    p = judge.noul(
        identity,
        "Do `name`, `tags`, or `description` indicate an internal, private, admin, back-office, database, batch, or worker component that should not be reachable from the internet?",
        NoulCriteria(
            true="Names or tags mention internal, private, admin, backoffice, ops, db, database, worker, batch, report, or an environment intended for staff only",
            false="Names or tags mention public, web, www, edge, cdn, api-gateway, ingress, marketing, or a customer-facing product",
        ),
    )
    if p >= judge.DEFAULT:
        report(f"'{identity['name']}' looks internal but is reachable from the internet {_percent(p)}")


# 11
def log_and_temp_buckets_have_lifecycle(args, report):
    """Buckets that hold logs, exports, scratch, or build artifacts must have lifecycle rules so data expires."""
    if args.resource_type != S3_BUCKET or args.props.get("lifecycleRules"):
        return
    identity = _identity(args)
    p = judge.noul(
        identity,
        "Do `name` or `tags` indicate the bucket stores logs, exports, scratch or temporary data, caches, or build artifacts that should expire?",
        NoulCriteria(
            true="Names or tags mention logs, access-logs, flow-logs, exports, scratch, tmp, temp, cache, artifacts, builds, or reports",
            false="Names or tags describe durable data such as uploads, documents, assets, media, backups, or a product's primary data",
        ),
    )
    if p >= judge.DEFAULT:
        report(f"bucket '{identity['name']}' looks like log or temporary storage and has no lifecycle rules {_percent(p)}")


# 12
def _env_pairs(args):
    t, p = args.resource_type, args.props
    if t == LAMBDA:
        env = p.get("environment")
        variables = env.get("variables") if isinstance(env, Mapping) else None
        return [(n, str(v), None) for n, v in (variables or {}).items()]
    if t == ECS_TASK:
        containers = p.get("containerDefinitions")
        if not containers:
            return []
        containers = json.loads(containers) if isinstance(containers, str) else judge.plain(containers)
        return [(e["name"], str(e.get("value", "")), c.get("name")) for c in containers for e in c.get("environment") or []]
    if t == CODEBUILD:
        env = p.get("environment")
        variables = env.get("environmentVariables") if isinstance(env, Mapping) else None
        return [(v["name"], str(v.get("value", "")), None) for v in judge.plain(variables or []) if (v.get("type") or "PLAINTEXT") == "PLAINTEXT"]
    return []


def no_plaintext_secrets_in_env(args, report):
    """Lambda, ECS, and CodeBuild environment variables must not carry credentials in plaintext."""
    pairs = _env_pairs(args)
    if not pairs:
        return
    state = {"variables": [{"name": n, "value_shape": judge.value_shape(v)} for n, v, _ in pairs]}
    questions = {
        f"var_{i}": Noul(
            instructions=f"Given its name and the shape of its value, is `variables[{i}]` a credential, API key, token, or password stored in plaintext?",
            criteria=NoulCriteria(
                true="The name suggests a secret (password, secret, token, key, credential, auth) and the value shape is consistent with a literal secret: long, mixed character classes, or a known credential prefix",
                false="The name is not secret-like, or the value shape looks like a URL, an ARN, a short setting such as 'info' or 'true', or a reference to a secret store",
            ),
        )
        for i in range(len(pairs))
    }
    answers = judge.ask(state, questions).nouls
    for i, (n, _, scope) in enumerate(pairs):
        p = answers[f"var_{i}"].noul
        if p >= judge.HIGH:
            where = f" in container '{scope}'" if scope else ""
            report(f"environment variable {n}{where} looks like a plaintext secret {_percent(p)}")


# 13
def tags_meaningful(args, report):
    """Owner, environment, and cost center tags must carry real values, not placeholders."""
    if args.resource_type.startswith(CONTROL_PLANE_PREFIXES):
        return
    tags = _tags(args)
    if tags is None:
        return
    state, questions = {}, {}
    owner_key, owner = _tag(tags, "owner")
    if owner_key:
        state["owner"] = owner
        questions["owner"] = Noul(
            instructions="Is `owner` a placeholder or filler value rather than the name of a real team or person?",
            criteria=NoulCriteria(
                true="todo, tbd, tba, n/a, none, test, asdf, me, someone, unknown, a single character, or a generic word such as admin or user",
                false="A team name, a person's name, an email address, a handle, or a group alias",
            ),
        )
    env = judge.env_tag(tags)
    if env:
        state["env"] = env[1]
        questions["env"] = Choice(instructions="Which environment does `env` identify?", criteria=judge.ENV_CRITERIA)
    cost_key, cost = next(((k, v) for k, v in tags.items() if k.lower() in COST_CENTER_KEYS), (None, None))
    if cost_key:
        state["cost_center"] = cost
        questions["cost_center"] = Noul(
            instructions="Is `cost_center` a placeholder rather than a plausible cost center, project code, or billing identifier?",
            criteria=NoulCriteria(true="n/a, none, todo, tbd, test, 0, x, or a generic word", false="A code, number, project name, or department that a finance team could bill"),
        )
    if not questions:
        return
    answers = judge.ask(state, questions)
    if owner_key and answers.nouls["owner"].noul >= judge.DEFAULT:
        report(f"owner tag '{owner}' looks like a placeholder {_percent(answers.nouls['owner'].noul)}")
    if env:
        a = answers.choices["env"]
        if a.choice == "unknown" or a.confidence < ENV_CONFIDENCE:
            report(f"environment tag '{env[1]}' is not a recognized environment (read as {a.choice}, confidence={a.confidence:.2f})")
    if cost_key and answers.nouls["cost_center"].noul >= judge.DEFAULT:
        report(f"cost center tag '{cost}' looks like a placeholder {_percent(answers.nouls['cost_center'].noul)}")


# 14
NAME_ENV_CRITERIA = {k: v for k, v in judge.ENV_CRITERIA.items() if k != "unknown"} | {"none": "The name carries no environment hint"}


def name_consistent_with_config(args, report):
    """A resource name that implies an environment must agree with the resource's environment tag."""
    if args.resource_type.startswith(CONTROL_PLANE_PREFIXES):
        return
    tags = _tags(args)
    env = judge.env_tag(tags) if tags else None
    if not env:
        return
    name = _identity(args)["name"]
    answers = judge.ask(
        {"name": name, "env_tag": env[1]},
        {
            "name_env": Choice(instructions="Which environment does `name` imply?", criteria=NAME_ENV_CRITERIA),
            "tag_env": Choice(instructions="Which environment does `env_tag` identify?", criteria=judge.ENV_CRITERIA),
        },
    ).choices
    by_name, by_tag = answers["name_env"], answers["tag_env"]
    if by_name.choice == "none" or by_tag.choice == "unknown":
        return
    if by_name.confidence < ENV_CONFIDENCE or by_tag.confidence < ENV_CONFIDENCE:
        return
    if by_name.choice != by_tag.choice:
        report(f"name '{name}' implies {by_name.choice} but the environment tag '{env[1]}' reads as {by_tag.choice}")


# 15
def sqs_work_queue_has_dlq(args, report):
    """Primary work queues must have a dead-letter queue configured through a redrive policy."""
    if args.resource_type != SQS_QUEUE or args.props.get("redrivePolicy"):
        return
    identity = _identity(args)
    p = judge.noul(
        identity | {"fifo": bool(args.props.get("fifoQueue"))},
        "Is this queue a primary work queue whose messages are processed by consumers, rather than a dead-letter queue or a queue that only receives notifications or fan-out copies?",
        NoulCriteria(
            true="Names or tags describe jobs, tasks, orders, events to process, or a worker pipeline",
            false="Names or tags contain dlq, dead-letter, failed, retry, or describe a notification, audit, or fan-out sink",
        ),
    )
    if p >= judge.DEFAULT:
        report(f"work queue '{identity['name']}' has no dead-letter queue {_percent(p)}")


class Rule(NamedTuple):
    name: str
    validate: Callable
    enforcement: EnforcementLevel
    severity: Severity


MANDATORY, ADVISORY = EnforcementLevel.MANDATORY, EnforcementLevel.ADVISORY

POLICIES = [
    Rule("resource-policy-not-open", resource_policy_not_open, MANDATORY, Severity.CRITICAL),
    Rule("sensitive-data-store-encrypted", sensitive_data_store_encrypted, MANDATORY, Severity.HIGH),
    Rule("prod-or-sensitive-store-protected", prod_or_sensitive_store_protected, MANDATORY, Severity.HIGH),
    Rule("iam-no-admin-equivalent", iam_no_admin_equivalent, MANDATORY, Severity.CRITICAL),
    Rule("iam-grant-matches-stated-purpose", iam_grant_matches_stated_purpose, ADVISORY, Severity.HIGH),
    Rule("iam-trust-policy-restricted", iam_trust_policy_restricted, MANDATORY, Severity.CRITICAL),
    Rule("iam-no-service-users", iam_no_service_users, ADVISORY, Severity.MEDIUM),
    Rule("sg-rule-matches-description", sg_rule_matches_description, MANDATORY, Severity.HIGH),
    Rule("sg-description-meaningful", sg_description_meaningful, ADVISORY, Severity.LOW),
    Rule("internal-resource-not-public", internal_resource_not_public, MANDATORY, Severity.HIGH),
    Rule("log-and-temp-buckets-have-lifecycle", log_and_temp_buckets_have_lifecycle, ADVISORY, Severity.LOW),
    Rule("no-plaintext-secrets-in-env", no_plaintext_secrets_in_env, MANDATORY, Severity.HIGH),
    Rule("tags-meaningful", tags_meaningful, ADVISORY, Severity.MEDIUM),
    Rule("name-consistent-with-config", name_consistent_with_config, ADVISORY, Severity.MEDIUM),
    Rule("sqs-work-queue-has-dlq", sqs_work_queue_has_dlq, ADVISORY, Severity.MEDIUM),
]
