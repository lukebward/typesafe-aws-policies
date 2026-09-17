"""Sixteen AWS good-usage policies.

Code decides every case it can decide exactly. The model only gets the gray zone: intent, purpose,
consistency between fields, and whether a condition or description means what it claims.

Each policy is a plain function under an @policy decorator. The decorator registers it, records the
resource types it applies to, and skips every other resource before the body runs. The question a
policy asks the model sits right above it as a Q_* constant.
"""
import json
import re
from collections.abc import Mapping
from fnmatch import fnmatchcase
from functools import wraps
from typing import Callable, NamedTuple

from pulumi_policy import EnforcementLevel, PolicyConfigSchema, Severity
from pulumi_policy.proxy import UnknownValueError
from typesafe_sdk import Choice, Noul, NoulCriteria, Score

import judge

MANDATORY, ADVISORY = EnforcementLevel.MANDATORY, EnforcementLevel.ADVISORY
ENV_CONFIDENCE = 0.6
CONTROL_PLANE_PREFIXES = ("pulumi:", "pulumiservice:")

S3_BUCKET = "aws:s3/bucket:Bucket"
RDS_INSTANCE, RDS_CLUSTER = "aws:rds/instance:Instance", "aws:rds/cluster:Cluster"
DYNAMODB_TABLE = "aws:dynamodb/table:Table"
IAM_POLICY_TYPES = ("aws:iam/policy:Policy", "aws:iam/rolePolicy:RolePolicy", "aws:iam/userPolicy:UserPolicy", "aws:iam/groupPolicy:GroupPolicy")
IAM_ROLE, IAM_NATIVE_ROLE, IAM_USER = "aws:iam/role:Role", "aws-native:iam:Role", "aws:iam/user:User"
SG, SG_RULE, VPC_INGRESS_RULE = "aws:ec2/securityGroup:SecurityGroup", "aws:ec2/securityGroupRule:SecurityGroupRule", "aws:vpc/securityGroupIngressRule:SecurityGroupIngressRule"
LAMBDA, ECS_TASK, CODEBUILD = "aws:lambda/function:Function", "aws:ecs/taskDefinition:TaskDefinition", "aws:codebuild/project:Project"
SQS_QUEUE = "aws:sqs/queue:Queue"


# --- registry -----------------------------------------------------------------------------------

class Rule(NamedTuple):
    name: str
    validate: Callable
    enforcement: EnforcementLevel
    severity: Severity
    config_schema: PolicyConfigSchema | None
    types: tuple | None  # None means any cloud resource


POLICIES: list[Rule] = []


def policy(name, enforcement, severity, types=None, config=None):
    """Register a validator and guard it so the body only runs for the resource types it covers."""
    def decorate(fn):
        @wraps(fn)
        def guarded(args, report):
            if types is None and args.resource_type.startswith(CONTROL_PLANE_PREFIXES):
                return
            if types is not None and args.resource_type not in types:
                return
            fn(args, report)
        POLICIES.append(Rule(name, guarded, enforcement, severity, config, tuple(types) if types else None))
        return guarded
    return decorate


# --- shared helpers -----------------------------------------------------------------------------

def _document(args, key):
    """A policy document input, or not-applicable when it is computed and unknown during preview."""
    try:
        return args.props.get(key)
    except UnknownValueError:
        args.not_applicable(f"{key} is not known during preview; the policy runs on update")


def _statements(doc):
    doc = json.loads(doc) if isinstance(doc, str) else judge.plain(doc)
    stmts = doc.get("Statement", [])
    return stmts if isinstance(stmts, list) else [stmts]


def _allow_statements(doc):
    return [s for s in _statements(doc) if s.get("Effect") == "Allow"] if doc else []


def _as_list(value):
    return [value] if isinstance(value, str) else list(value or [])


def _tags(args):
    tags = args.props.get("tags")
    return tags if isinstance(tags, Mapping) else None


def _tag(tags, key):
    return next(((k, v) for k, v in tags.items() if k.lower() == key), (None, None))


def _display_name(args, *keys):
    """The explicit physical name when one is set; the logical name when Pulumi auto-named the resource."""
    physical = next((args.props.get(k) for k in keys if args.props.get(k)), None)
    if not physical or re.fullmatch(re.escape(args.name) + r"-?[0-9a-f]{7}", physical):
        return args.name
    return physical


def _identity(args):
    name = _display_name(args, "functionName", "name", "bucket", "identifier")
    return {"resource_type": args.resource_type, "name": name, "tags": judge.plain(_tags(args) or {}), "description": args.props.get("description")}


def _wildcard_principal(stmt):
    principal = stmt.get("Principal")
    return principal == "*" or (isinstance(principal, Mapping) and "*" in _as_list(principal.get("AWS")))


def _percent(p):
    return f"(p={p:.2f})"


SENSITIVE_QUESTION = "Do `name`, `tags`, or `description` suggest this store holds sensitive data such as personal data, customer records, health or financial records, credentials, backups, or audit logs?"
SENSITIVE_CRITERIA = NoulCriteria(
    true="Names or tags mention customers, users, PII, patients, payments, finance, secrets, credentials, backups, audit, compliance, or a regulated data class",
    false="Names or tags describe public assets, static sites, scratch or test data, caches, or build artifacts",
)


# --- 1 resource policies -------------------------------------------------------------------------

RESOURCE_POLICY_TYPES = ("aws:s3/bucketPolicy:BucketPolicy", "aws:kms/key:Key", "aws:sqs/queuePolicy:QueuePolicy", "aws:sns/topicPolicy:TopicPolicy", "aws:secretsmanager/secretPolicy:SecretPolicy")

Q_CONDITION_LIMITS_CALLER = (
    "Does `statements[{i}]` still allow callers from outside the owning account or organization despite its Condition?",
    NoulCriteria(
        true="The Condition only constrains how the call is made, such as aws:SecureTransport, request headers, user agent, encryption settings, or broad IP ranges, and not who makes it",
        false="The Condition restricts the caller to an organization, account, VPC endpoint, or source resource, such as aws:PrincipalOrgID, aws:PrincipalAccount, aws:SourceVpce, aws:SourceArn, aws:SourceAccount, or kms:CallerAccount",
    ),
)


@policy("resource-policy-not-open", MANDATORY, Severity.CRITICAL, types=RESOURCE_POLICY_TYPES)
def resource_policy_not_open(args, report):
    """Resource policies on S3, KMS, SQS, SNS, and Secrets Manager must not let anonymous or arbitrary principals in."""
    gray = []
    for stmt in _allow_statements(_document(args, "policy")):
        if not _wildcard_principal(stmt):
            continue
        if stmt.get("Condition"):
            gray.append(stmt)
        else:
            report("statement allows every principal and has no Condition")
    for p in judge.noul_each({"statements": gray}, "statements", *Q_CONDITION_LIMITS_CALLER):
        if p >= judge.DEFAULT:
            report(f"statement allows every principal and its Condition does not limit who can call {_percent(p)}")


# --- 2 encryption at rest ------------------------------------------------------------------------

ENCRYPTED = {
    S3_BUCKET: lambda p: bool(p.get("serverSideEncryptionConfiguration")),
    RDS_INSTANCE: lambda p: p.get("storageEncrypted") is True,
    RDS_CLUSTER: lambda p: p.get("storageEncrypted") is True,
    DYNAMODB_TABLE: lambda p: bool((p.get("serverSideEncryption") or {}).get("enabled")),
    "aws:ebs/volume:Volume": lambda p: p.get("encrypted") is True,
    "aws:efs/fileSystem:FileSystem": lambda p: p.get("encrypted") is True,
}


@policy("sensitive-data-store-encrypted", MANDATORY, Severity.HIGH, types=tuple(ENCRYPTED))
def sensitive_data_store_encrypted(args, report):
    """Data stores whose name, tags, or description suggest sensitive data must encrypt data at rest."""
    if ENCRYPTED[args.resource_type](args.props):
        return
    p = judge.noul(_identity(args), SENSITIVE_QUESTION, SENSITIVE_CRITERIA)
    if p >= judge.DEFAULT:
        report(f"store looks sensitive and is not encrypted at rest {_percent(p)}")


# --- 3 backups and recovery ----------------------------------------------------------------------

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


def _prod_and_sensitive(args):
    """One request: is the store production (from its env tag) and does it look sensitive."""
    state = _identity(args)
    questions = {"sensitive": Noul(instructions=SENSITIVE_QUESTION, criteria=SENSITIVE_CRITERIA)}
    env = judge.env_tag(state["tags"])
    if env:
        state["env_tag"] = {"key": env[0], "value": env[1]}
        questions["env"] = Choice(instructions="Which environment does `env_tag.value` identify?", criteria=judge.ENV_CRITERIA)
    answers = judge.ask(state, questions)
    prod = bool(env) and answers.choices["env"].choice == "production" and answers.choices["env"].confidence >= ENV_CONFIDENCE
    return prod, answers.nouls["sensitive"].noul


@policy("prod-or-sensitive-store-protected", MANDATORY, Severity.HIGH, types=(RDS_INSTANCE, RDS_CLUSTER, S3_BUCKET, DYNAMODB_TABLE))
def prod_or_sensitive_store_protected(args, report):
    """Production or sensitive data stores must keep backups, versioning or point-in-time recovery, and deletion protection."""
    gaps = _protection_gaps(args)
    if not gaps:
        return
    prod, sensitive = _prod_and_sensitive(args)
    if not prod and sensitive < judge.DEFAULT:
        return
    reason = "production store" if prod else f"sensitive store {_percent(sensitive)}"
    for gap in gaps:
        report(f"{reason}: {gap}")


# --- 4 privilege escalation ----------------------------------------------------------------------

ESCALATION_CATALOG = {
    "iam:PassRole": "pass-role",
    "lambda:CreateFunction": "create-compute", "lambda:UpdateFunctionCode": "create-compute", "lambda:UpdateFunctionConfiguration": "create-compute",
    "ec2:RunInstances": "create-compute", "ecs:RunTask": "create-compute", "ecs:RegisterTaskDefinition": "create-compute",
    "glue:CreateDevEndpoint": "create-compute", "glue:CreateJob": "create-compute", "glue:UpdateJob": "create-compute",
    "cloudformation:CreateStack": "create-compute", "cloudformation:UpdateStack": "create-compute",
    "codebuild:CreateProject": "create-compute", "codebuild:UpdateProject": "create-compute",
    "sagemaker:CreateNotebookInstance": "create-compute", "sagemaker:CreateTrainingJob": "create-compute", "sagemaker:CreateProcessingJob": "create-compute",
    "datapipeline:CreatePipeline": "create-compute", "datapipeline:PutPipelineDefinition": "create-compute",
    "iam:CreatePolicyVersion": "write-policy", "iam:SetDefaultPolicyVersion": "activate-policy",
    "iam:AttachUserPolicy": "attach-policy", "iam:AttachRolePolicy": "attach-policy", "iam:AttachGroupPolicy": "attach-policy",
    "iam:PutUserPolicy": "attach-policy", "iam:PutRolePolicy": "attach-policy", "iam:PutGroupPolicy": "attach-policy",
    "iam:UpdateAssumeRolePolicy": "attach-policy", "iam:AddUserToGroup": "attach-policy",
    "iam:CreateAccessKey": "create-credentials", "iam:CreateLoginProfile": "create-credentials", "iam:UpdateLoginProfile": "create-credentials",
}
ESCALATION_CHAINS = ({"pass-role", "create-compute"}, {"write-policy", "activate-policy"}, {"attach-policy"}, {"create-credentials"})
CATALOG_SERVICES = {action.split(":")[0] for action in ESCALATION_CATALOG}

Q_SERVICE_RUNS_PASSED_ROLE = (
    "Can any service in `services` create or run compute, jobs, notebooks, functions, or stacks that execute under an IAM role passed to it with iam:PassRole?",
    NoulCriteria(
        true="At least one listed service launches code or jobs that assume a passed role, such as Lambda, EC2, ECS, Batch, Glue, SageMaker, CodeBuild, CloudFormation, Data Pipeline, EMR, or EKS",
        false="None of the listed services execute code or jobs under a passed role; they only store data, route traffic, or manage DNS, billing, or monitoring",
    ),
)


def _matches(action, patterns):
    return any(fnmatchcase(action.lower(), p.lower()) for p in patterns)


def _broad_allow_statements(stmts):
    return [s for s in stmts if "*" in _as_list(s.get("Resource"))]


def _capabilities(stmts):
    """Escalation capabilities the policy grants on every resource, wildcards and NotAction included."""
    caps = set()
    for stmt in _broad_allow_statements(stmts):
        for action, cap in ESCALATION_CATALOG.items():
            allowed = not _matches(action, _as_list(stmt["NotAction"])) if "NotAction" in stmt else _matches(action, _as_list(stmt.get("Action")))
            if allowed:
                caps.add(cap)
    return caps


def _unknown_wildcard_services(stmts):
    services = set()
    for stmt in _broad_allow_statements(stmts):
        for pattern in _as_list(stmt.get("Action")):
            service, _, rest = pattern.partition(":")
            if rest == "*" and service != "*" and service not in CATALOG_SERVICES:
                services.add(service)
    return sorted(services)


@policy("iam-no-admin-equivalent", MANDATORY, Severity.CRITICAL, types=IAM_POLICY_TYPES)
def iam_no_admin_equivalent(args, report):
    """IAM policies must not grant administrator-equivalent access, directly or through an escalation path."""
    stmts = _allow_statements(_document(args, "policy"))
    caps = _capabilities(stmts)
    for chain in ESCALATION_CHAINS:
        if chain <= caps:
            report(f"policy grants a privilege escalation chain: {' + '.join(sorted(chain))} on every resource")
            return
    services = _unknown_wildcard_services(stmts)
    if "pass-role" not in caps or not services:
        return
    p = judge.noul({"services": services, "holder_also_has": "iam:PassRole on every role"}, *Q_SERVICE_RUNS_PASSED_ROLE)
    if p >= judge.DEFAULT:
        report(f"iam:PassRole plus full access to {', '.join(services)} can run code under any role {_percent(p)}")


# --- 5 purpose fit -------------------------------------------------------------------------------

Q_GRANT_FIT = Score(
    instructions="Compare the permissions in `statements` with the purpose stated by `policy_name` and `description`. How far does the grant go beyond that purpose?",
    criteria=[
        "The grant matches the stated purpose: only the actions and resources that purpose needs",
        "The grant is somewhat broader than the stated purpose, such as extra read access or a wildcard on the one service the purpose names",
        "The grant is far broader than the stated purpose, such as full access to unrelated services, wildcard actions, or IAM permissions the purpose does not mention",
    ],
)


@policy("iam-grant-matches-stated-purpose", ADVISORY, Severity.HIGH, types=IAM_POLICY_TYPES)
def iam_grant_matches_stated_purpose(args, report):
    """An IAM policy's grants must match the purpose stated by its name and description."""
    state = {
        "policy_name": _display_name(args, "name"),
        "description": args.props.get("description"),
        "tags": judge.plain(_tags(args) or {}),
        "statements": _statements(_document(args, "policy")),
    }
    score = judge.ask(state, {"fit": Q_GRANT_FIT}).scores["fit"].score
    if score >= 1.5:
        report(f"grant goes far beyond the stated purpose of '{state['policy_name']}' (score={score:.1f} of 2)")


# --- 6 trust policies ----------------------------------------------------------------------------

RESTRICTING_CONDITION_KEYS = {"sts:externalid", "aws:principalorgid", "aws:principalarn", "aws:sourcearn", "aws:sourceaccount", "aws:principalaccount"}
ACCOUNT_WIDE = re.compile(r"^(\d{12}|arn:aws:iam::\d{12}:root)$")
GRAY_TRUST_KINDS = {"federated", "wildcard-conditioned", "account-wide-conditioned", "identity-conditioned"}
TRUST_CONFIG = PolicyConfigSchema(properties={
    "ownAccountId": {"type": "string", "description": "The AWS account that owns the stack. Same-account root trust is accepted."},
    "trustedAccountIds": {"type": "array", "items": {"type": "string"}, "description": "Other accounts allowed to assume roles without a condition."},
})

Q_TRUST_PINNED = (
    "Given `statements[{i}].principal_kind`, `principal`, and `condition`, can identities beyond one specific workload or one named role assume this role?",
    NoulCriteria(
        true="A federated condition uses a wildcard that matches many repositories, branches, subjects, or users (for example sub: repo:org/*:*), or an AWS principal's condition value is a wildcard that matches many roles or accounts",
        false="The condition pins one repository and branch, one subject, one audience with one subject, one sts:ExternalId, one organization, or one named role ARN",
    ),
)


def classify_trust(stmt):
    """What kind of principal a trust statement admits, and the AWS account it names."""
    principal = stmt.get("Principal") or {}
    conditioned = bool(stmt.get("Condition"))
    if _wildcard_principal(stmt):
        return ("wildcard-conditioned" if conditioned else "wildcard-open", None)
    if not isinstance(principal, Mapping):
        return ("other", None)
    if "Federated" in principal:
        return ("federated", None)
    if set(principal) == {"Service"}:
        return ("service", None)
    aws = _as_list(principal.get("AWS"))
    if not aws:
        return ("other", None)
    account = re.sub(r"\D", "", aws[0])[:12] or None
    if any(ACCOUNT_WIDE.match(a) for a in aws):
        keys = {k.lower() for op in (stmt.get("Condition") or {}).values() for k in op}
        return ("account-wide-conditioned" if keys & RESTRICTING_CONDITION_KEYS else "account-wide-open", account)
    return ("identity-conditioned" if conditioned else "identity-open", account)


def _trust_digest(stmt):
    kind, _ = classify_trust(stmt)
    principal_kind = "federated" if kind == "federated" else "aws-account" if kind.startswith("account-wide") else "aws-identity"
    condition = stmt.get("Condition") or {}
    return {"principal_kind": principal_kind, "principal": stmt.get("Principal"), "condition_keys": [k for op in condition.values() for k in op], "condition": condition}


def _trust_statements(args):
    key = "assumeRolePolicyDocument" if args.resource_type == IAM_NATIVE_ROLE else "assumeRolePolicy"
    return _allow_statements(_document(args, key))


def _trusted_accounts(args):
    config = args.get_config() or {}
    own = config.get("ownAccountId")
    return own, set(config.get("trustedAccountIds") or []) | ({own} if own else set())


@policy("iam-trust-policy-restricted", MANDATORY, Severity.CRITICAL, types=(IAM_ROLE, IAM_NATIVE_ROLE), config=TRUST_CONFIG)
def iam_trust_policy_restricted(args, report):
    """IAM role trust policies must pin who can assume the role, including federated subjects and cross-account conditions."""
    own, trusted = _trusted_accounts(args)
    gray = []
    for stmt in _trust_statements(args):
        kind, account = classify_trust(stmt)
        if kind == "wildcard-open":
            report("trust policy lets every principal assume the role with no Condition")
        elif kind == "account-wide-open" and own and account not in trusted:
            report(f"trust policy lets every identity in account {account} assume the role without sts:ExternalId, aws:PrincipalArn, or an organization condition")
        elif kind in GRAY_TRUST_KINDS:
            gray.append(_trust_digest(stmt))
    for p in judge.noul_each({"statements": gray}, "statements", *Q_TRUST_PINNED):
        if p >= judge.DEFAULT:
            report(f"trust policy statement lets untrusted principals assume the role {_percent(p)}")


@policy("iam-trust-account-wide", ADVISORY, Severity.MEDIUM, types=(IAM_ROLE, IAM_NATIVE_ROLE), config=TRUST_CONFIG)
def iam_trust_account_wide(args, report):
    """Roles that any identity in an account can assume should be reviewed. Set ownAccountId to accept same-account trust."""
    own, trusted = _trusted_accounts(args)
    for stmt in _trust_statements(args):
        kind, account = classify_trust(stmt)
        if kind == "account-wide-open" and account not in trusted:
            hint = "" if own else "; set ownAccountId in the policy config to accept same-account trust"
            report(f"any identity in account {account} with sts:AssumeRole permission can assume this role{hint}")


# --- 7 IAM users ---------------------------------------------------------------------------------

Q_SERVICE_USER = (
    "Does `user_name` identify a machine, service, application, pipeline, or bot rather than a person?",
    NoulCriteria(true="Names like ci-deploy, app-svc, terraform, backup-bot, jenkins, github-actions, or a product name", false="A person's name, initials, or handle such as jane.doe or jdoe"),
)


@policy("iam-no-service-users", ADVISORY, Severity.MEDIUM, types=(IAM_USER,))
def iam_no_service_users(args, report):
    """IAM users are for people. Machine and service identities should use roles."""
    user_name = _display_name(args, "name")
    p = judge.noul({"user_name": user_name}, *Q_SERVICE_USER)
    if p >= judge.DEFAULT:
        report(f"IAM user '{user_name}' looks like a service identity; use a role instead {_percent(p)}")


# --- 8 and 9 security groups ---------------------------------------------------------------------

RULE_FIELDS = ("fromPort", "toPort", "protocol", "cidrBlocks", "ipv6CidrBlocks", "description")

Q_RULE_MATCHES_DESCRIPTION = (
    "Does `rules[{i}]` allow substantially more traffic than its `description` claims, in ports, protocol, or source?",
    NoulCriteria(
        true="The description names a narrower service, port, or source than the rule permits, for example 'HTTPS from the ALB' on a rule that opens all ports to 0.0.0.0/0",
        false="The description accurately covers the ports, protocol, and source the rule allows",
    ),
)
Q_DESCRIPTION_QUALITY = Score(
    instructions="How well does `description` explain what this security group is for and what traffic it allows?",
    criteria=[
        "Empty, a placeholder, or a default such as 'Managed by Pulumi', 'sg', or 'security group'",
        "Names a component but not its purpose or traffic, such as 'web' or 'db sg'",
        "States the component and the traffic it allows, such as 'Allows HTTPS from the ALB to the API service'",
    ],
)


def _port(value):
    return int(value) if isinstance(value, float) and value.is_integer() else value


def _ingress_rules(args):
    t, p = args.resource_type, judge.plain(args.props)
    if t == SG:
        rules = p.get("ingress") or []
    elif t == SG_RULE and p.get("type") == "ingress":
        rules = [p]
    elif t == VPC_INGRESS_RULE:
        rules = [{"fromPort": p.get("fromPort"), "toPort": p.get("toPort"), "protocol": p.get("ipProtocol"), "description": p.get("description"),
                  "cidrBlocks": [p["cidrIpv4"]] if p.get("cidrIpv4") else [], "ipv6CidrBlocks": [p["cidrIpv6"]] if p.get("cidrIpv6") else []}]
    else:
        return []
    for r in rules:
        r["fromPort"], r["toPort"] = _port(r.get("fromPort")), _port(r.get("toPort"))
    return rules


def _sources(rule):
    return (rule.get("cidrBlocks") or []) + (rule.get("ipv6CidrBlocks") or [])


def _is_public(rule):
    return any(judge.is_public_cidr(c) for c in _sources(rule))


def _is_broad(rule):
    return str(rule.get("protocol")) == "-1" or (rule.get("fromPort") == 0 and rule.get("toPort") == 65535)


def _rule_label(rule):
    return f"{rule.get('protocol')} {rule.get('fromPort')}-{rule.get('toPort')} from {', '.join(_sources(rule)) or 'unspecified'}"


@policy("sg-rule-matches-description", MANDATORY, Severity.HIGH, types=(SG, SG_RULE, VPC_INGRESS_RULE))
def sg_rule_matches_description(args, report):
    """Public or broad security group rules must carry a description that matches what the rule actually allows."""
    rules = [r for r in _ingress_rules(args) if _is_public(r) or _is_broad(r)]
    for r in rules:
        if not r.get("description"):
            report(f"ingress {_rule_label(r)} is public or broad and has no description")
    described = [r for r in rules if r.get("description")]
    state = {"rules": [{k: r.get(k) for k in RULE_FIELDS} for r in described]}
    for r, p in zip(described, judge.noul_each(state, "rules", *Q_RULE_MATCHES_DESCRIPTION)):
        if p >= judge.DEFAULT:
            report(f"ingress {_rule_label(r)} allows more than its description '{r['description']}' claims {_percent(p)}")


@policy("sg-description-meaningful", ADVISORY, Severity.LOW, types=(SG,))
def sg_description_meaningful(args, report):
    """Security group descriptions must explain what the group is for and what traffic it allows."""
    description = args.props.get("description") or ""
    score = judge.ask({"description": description}, {"quality": Q_DESCRIPTION_QUALITY}).scores["quality"].score
    if score < 1.0:
        report(f"description '{description}' does not explain the group's purpose (score={score:.1f} of 2)")


# --- 10 internet exposure ------------------------------------------------------------------------

PUBLIC = {
    "aws:ec2/instance:Instance": lambda p: p.get("associatePublicIpAddress") is True,
    RDS_INSTANCE: lambda p: p.get("publiclyAccessible") is True,
    RDS_CLUSTER: lambda p: p.get("publiclyAccessible") is True,
    "aws:lb/loadBalancer:LoadBalancer": lambda p: p.get("internal") is not True,
    "aws:alb/loadBalancer:LoadBalancer": lambda p: p.get("internal") is not True,
    "aws:lambda/functionUrl:FunctionUrl": lambda p: p.get("authorizationType") == "NONE",
}

Q_LOOKS_INTERNAL = (
    "Do `name`, `tags`, or `description` indicate an internal, private, admin, back-office, database, batch, or worker component that should not be reachable from the internet?",
    NoulCriteria(
        true="Names or tags mention internal, private, admin, backoffice, ops, db, database, worker, batch, report, or an environment intended for staff only",
        false="Names or tags mention public, web, www, edge, cdn, api-gateway, ingress, marketing, or a customer-facing product",
    ),
)


@policy("internal-resource-not-public", MANDATORY, Severity.HIGH, types=tuple(PUBLIC))
def internal_resource_not_public(args, report):
    """Resources that look internal (admin, back office, worker, database) must not be reachable from the internet."""
    if not PUBLIC[args.resource_type](args.props):
        return
    identity = _identity(args)
    p = judge.noul(identity, *Q_LOOKS_INTERNAL)
    if p >= judge.DEFAULT:
        report(f"'{identity['name']}' looks internal but is reachable from the internet {_percent(p)}")


# --- 11 bucket lifecycle -------------------------------------------------------------------------

Q_EXPIRING_DATA = (
    "Do `name` or `tags` indicate the bucket stores logs, exports, scratch or temporary data, caches, or build artifacts that should expire?",
    NoulCriteria(
        true="Names or tags mention logs, access-logs, flow-logs, exports, scratch, tmp, temp, cache, artifacts, builds, or reports",
        false="Names or tags describe durable data such as uploads, documents, assets, media, backups, or a product's primary data",
    ),
)


@policy("log-and-temp-buckets-have-lifecycle", ADVISORY, Severity.LOW, types=(S3_BUCKET,))
def log_and_temp_buckets_have_lifecycle(args, report):
    """Buckets that hold logs, exports, scratch, or build artifacts must have lifecycle rules so data expires."""
    if args.props.get("lifecycleRules"):
        return
    identity = _identity(args)
    p = judge.noul(identity, *Q_EXPIRING_DATA)
    if p >= judge.DEFAULT:
        report(f"bucket '{identity['name']}' looks like log or temporary storage and has no lifecycle rules {_percent(p)}")


# --- 12 plaintext secrets ------------------------------------------------------------------------

Q_PLAINTEXT_SECRET = (
    "Given its name and the shape of its value, is `variables[{i}]` a credential, API key, token, or password stored in plaintext?",
    NoulCriteria(
        true="The name suggests a secret (password, secret, token, key, credential, auth) and the value shape is consistent with a literal secret: long, mixed character classes, or a known credential prefix",
        false="The name is not secret-like, or the value shape looks like a URL, an ARN, a short setting such as 'info' or 'true', or a reference to a secret store",
    ),
)


def _env_pairs(args):
    """(name, value, container) for every plaintext environment variable the resource defines."""
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


@policy("no-plaintext-secrets-in-env", MANDATORY, Severity.HIGH, types=(LAMBDA, ECS_TASK, CODEBUILD))
def no_plaintext_secrets_in_env(args, report):
    """Lambda, ECS, and CodeBuild environment variables must not carry credentials in plaintext."""
    pairs = _env_pairs(args)
    state = {"variables": [{"name": n, "value_shape": judge.value_shape(v)} for n, v, _ in pairs]}
    for (name, _, container), p in zip(pairs, judge.noul_each(state, "variables", *Q_PLAINTEXT_SECRET)):
        if p >= judge.HIGH:
            where = f" in container '{container}'" if container else ""
            report(f"environment variable {name}{where} looks like a plaintext secret {_percent(p)}")


# --- 13 and 14 tags and names --------------------------------------------------------------------

COST_CENTER_KEYS = ("cost-center", "costcenter", "cost_center")

Q_OWNER_PLACEHOLDER = Noul(
    instructions="Is `owner` a placeholder or filler value rather than the name of a real team or person?",
    criteria=NoulCriteria(true="todo, tbd, tba, n/a, none, test, asdf, me, someone, unknown, a single character, or a generic word such as admin or user",
                          false="A team name, a person's name, an email address, a handle, or a group alias"),
)
Q_ENV_OF_TAG = Choice(instructions="Which environment does `env` identify?", criteria=judge.ENV_CRITERIA)
Q_COST_CENTER_PLACEHOLDER = Noul(
    instructions="Is `cost_center` a placeholder rather than a plausible cost center, project code, or billing identifier?",
    criteria=NoulCriteria(true="n/a, none, todo, tbd, test, 0, x, or a generic word", false="A code, number, project name, or department that a finance team could bill"),
)


@policy("tags-meaningful", ADVISORY, Severity.MEDIUM)
def tags_meaningful(args, report):
    """Owner, environment, and cost center tags must carry real values, not placeholders."""
    tags = _tags(args)
    if tags is None:
        return
    state, questions = {}, {}
    owner_key, owner = _tag(tags, "owner")
    env = judge.env_tag(tags)
    cost_key, cost = next(((k, v) for k, v in tags.items() if k.lower() in COST_CENTER_KEYS), (None, None))
    if owner_key:
        state["owner"], questions["owner"] = owner, Q_OWNER_PLACEHOLDER
    if env:
        state["env"], questions["env"] = env[1], Q_ENV_OF_TAG
    if cost_key:
        state["cost_center"], questions["cost_center"] = cost, Q_COST_CENTER_PLACEHOLDER
    if not questions:
        return
    answers = judge.ask(state, questions)
    if owner_key and answers.nouls["owner"].noul >= judge.DEFAULT:
        report(f"owner tag '{owner}' looks like a placeholder {_percent(answers.nouls['owner'].noul)}")
    if env and (answers.choices["env"].choice == "unknown" or answers.choices["env"].confidence < ENV_CONFIDENCE):
        a = answers.choices["env"]
        report(f"environment tag '{env[1]}' is not a recognized environment (read as {a.choice}, confidence={a.confidence:.2f})")
    if cost_key and answers.nouls["cost_center"].noul >= judge.DEFAULT:
        report(f"cost center tag '{cost}' looks like a placeholder {_percent(answers.nouls['cost_center'].noul)}")


NAME_ENV_CRITERIA = {k: v for k, v in judge.ENV_CRITERIA.items() if k != "unknown"} | {"none": "The name carries no environment hint"}
ENV_CLASS = {"production": "production", "staging": "staging", "development": "non-production", "test": "non-production"}
Q_ENV_OF_NAME = Choice(instructions="Which environment does `name` imply?", criteria=NAME_ENV_CRITERIA)
Q_ENV_OF_ENV_TAG = Choice(instructions="Which environment does `env_tag` identify?", criteria=judge.ENV_CRITERIA)


@policy("name-consistent-with-config", ADVISORY, Severity.MEDIUM)
def name_consistent_with_config(args, report):
    """A resource name that implies an environment must agree with the resource's environment tag."""
    tags = _tags(args)
    env = judge.env_tag(tags) if tags else None
    if not env:
        return
    name = _identity(args)["name"]
    answers = judge.ask({"name": name, "env_tag": env[1]}, {"name_env": Q_ENV_OF_NAME, "tag_env": Q_ENV_OF_ENV_TAG}).choices
    by_name, by_tag = answers["name_env"], answers["tag_env"]
    if by_name.choice == "none" or by_tag.choice == "unknown":
        return
    if by_name.confidence < ENV_CONFIDENCE or by_tag.confidence < ENV_CONFIDENCE:
        return
    if ENV_CLASS[by_name.choice] != ENV_CLASS[by_tag.choice]:
        report(f"name '{name}' implies {by_name.choice} but the environment tag '{env[1]}' reads as {by_tag.choice}")


# --- 15 queues -----------------------------------------------------------------------------------

Q_WORK_QUEUE = (
    "Is this queue a primary work queue whose messages are processed by consumers, rather than a dead-letter queue or a queue that only receives notifications or fan-out copies?",
    NoulCriteria(true="Names or tags describe jobs, tasks, orders, events to process, or a worker pipeline",
                 false="Names or tags contain dlq, dead-letter, failed, retry, or describe a notification, audit, or fan-out sink"),
)


@policy("sqs-work-queue-has-dlq", ADVISORY, Severity.MEDIUM, types=(SQS_QUEUE,))
def sqs_work_queue_has_dlq(args, report):
    """Primary work queues must have a dead-letter queue configured through a redrive policy."""
    if args.props.get("redrivePolicy"):
        return
    identity = _identity(args)
    p = judge.noul(identity | {"fifo": bool(args.props.get("fifoQueue"))}, *Q_WORK_QUEUE)
    if p >= judge.DEFAULT:
        report(f"work queue '{identity['name']}' has no dead-letter queue {_percent(p)}")


POLICIES_BY_NAME = {rule.name: rule for rule in POLICIES}
