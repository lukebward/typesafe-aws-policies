# typesafe-aws-policies

A Pulumi CrossGuard policy pack for AWS where each rule is a plain-English question answered by
[TypeSafe](https://typesafe.ai)'s Jev model.

The idea in one line: **code decides every case it can decide exactly, and the model only gets the
gray zone.** A wildcard principal with no condition is a violation without any AI call. Whether the
condition that *is* there actually limits who can call is a question for the model.

## How a policy works

```
resource inputs
      │
      ▼
 exact checks in code ──── clear violation ───────────────► report
      │
      ▼ only the ambiguous residue
 small JSON state + a typed question ──► TypeSafe (~100 ms) ──► probability
      │
      ▼
 threshold in code ─────────────────────────────────────────► report or pass
```

The model never writes text and never decides what to do. It returns a probability (Noul), a pick
from a fixed set (Choice), or a position on a rubric (Score). Code owns the thresholds.

## Quick start

```sh
uv venv venv --python 3.13
uv pip install --python venv/bin/python -r requirements.txt
echo "TYPESAFE_API_KEY=..." > .env        # gitignored; or export the variable

venv/bin/python -m pytest -q test_judge.py test_policies.py test_audit.py   # 93 tests, no network
venv/bin/python -m pytest -q test_live.py -s                                 # 44 cases against the real model
```

Run it against any stack from that stack's project directory:

```sh
pulumi preview --policy-pack ~/Workspace/Pulumi/typesafe-aws-policies \
  --policy-pack-config ~/Workspace/Pulumi/typesafe-aws-policies/examples/policy-config.example.json
```

Set `ownAccountId` in the config file to the stack's AWS account. Same-account root trust is a common,
intentional pattern and is then accepted; without the config it shows as an advisory so nothing blocks.

## The policies

| Policy | Resources | Code decides | Model decides |
| --- | --- | --- | --- |
| resource-policy-not-open | S3, KMS, SQS, SNS, Secrets Manager policies | wildcard principal with no Condition | does the Condition limit *who* can call, or only *how* |
| sensitive-data-store-encrypted | S3, RDS, DynamoDB, EBS, EFS | the per-type encryption field | do name, tags, description indicate sensitive data |
| prod-or-sensitive-store-protected | RDS, S3, DynamoDB | backups, deletion protection, multi-AZ, versioning, PITR | is this production, is this sensitive |
| iam-no-admin-equivalent | IAM policies | known escalation chains from an action catalog, wildcards and NotAction included | can an unlisted service wildcard plus PassRole run code under a passed role |
| iam-grant-matches-stated-purpose | IAM policies | none | Score: does the grant match the name and description, go somewhat beyond, or far beyond |
| iam-trust-policy-restricted | IAM roles (aws, aws-native) | `Principal: *` with no Condition; cross-account root trust when `ownAccountId` is set; service principals and named roles skipped | federated subject breadth (`repo:org/*:*`) and whether conditioned principals are really pinned |
| iam-trust-account-wide | IAM roles (aws, aws-native) | account-wide root trust without a restricting condition, unless the account is own or trusted | none |
| iam-no-service-users | IAM users | none | does the user name identify a machine rather than a person |
| sg-rule-matches-description | security groups, ingress rules | rule is public or broad; missing description | does the rule allow more than its description claims |
| sg-description-meaningful | security groups | none | Score on description quality |
| internal-resource-not-public | EC2, RDS, load balancers, Lambda URLs | the per-type public flag | do name, tags, description indicate an internal component |
| log-and-temp-buckets-have-lifecycle | S3 | lifecycle rules present | is this bucket for logs, exports, scratch, or artifacts |
| no-plaintext-secrets-in-env | Lambda, ECS task definitions, CodeBuild | value shape computed locally, the value itself never leaves the process | given name and shape, is this a plaintext credential |
| tags-meaningful | any resource with tags | which tags are present | owner is real, env is recognized, cost center is plausible |
| name-consistent-with-config | any resource with an env tag | env tag present | does the name imply a different environment than the tag |
| sqs-work-queue-has-dlq | SQS queues | redrive policy present | is this a primary work queue rather than a DLQ or fan-out sink |

Security policies are MANDATORY. Hygiene policies (purpose fit, names, descriptions, tags, IAM users,
lifecycle, DLQ, account-wide trust) are ADVISORY. Set `"all": {"enforcementLevel": "advisory"}` in
the config file to start advisory-only.

## Reading the code

- `policies.py` is the whole pack. Each policy is one short function under an `@policy(...)` decorator
  that names it, sets enforcement and severity, and lists the resource types it applies to. The
  question the policy asks sits right above it as a `Q_*` constant, so tuning a question is a one-line
  edit and the function body reads as plain logic.
- `judge.py` is the only file that talks to TypeSafe: the API key, an in-process cache, `noul` for one
  question, `noul_each` for one question over every item in a list, the shared environment Choice,
  and `value_shape`, which describes a string without revealing it.
- `audit.py` runs every policy over `pulumi stack export` output and prints each verdict, passes
  included, because a preview only shows violations.
- `examples/demo` is a stack with compliant and violating resources for every policy. `pulumi preview`
  on it needs no AWS credentials; the README command sets dummy keys and `aws:skipCredentialsValidation`.

## Seeing every verdict

```sh
venv/bin/python audit.py --stack org/stack --config examples/policy-config.example.json
```

## What the live runs taught us

- **Give the model facts, not raw JSON.** Raw IAM statements scored 0.52 to 0.59 on escalation chains.
  The same cases scored 0.81 to 0.98 once code extracted the relevant actions and principal kinds.
  Better still, most of those cases turned out to be decidable in code, so they never reach the model.
- **Thresholds are not the fix.** `DEFAULT = 0.8` and `HIGH = 0.85` in `judge.py` never moved. On the
  live suite every intended violation scored 0.85 or higher and every intended pass 0.20 or lower.
- **Jev is literal.** Arithmetic, dates, counting, and CIDR math stay in code. Environment names are
  classified into a fixed set, and dev and test count as one class so `ci-scratch` next to `env: dev`
  is not a mismatch.
- **Unknowns in preview.** A policy document computed from other resources is unknown during preview.
  Those policies mark themselves not applicable for that preview and evaluate on `pulumi up`.

## Limits

- The S3 checks read the inline `serverSideEncryptionConfiguration`, `versioning`, and `lifecycleRules`
  inputs on `aws.s3.Bucket`. Stacks that use the separate configuration resources need a stack-level
  policy instead.
- One request per policy per resource. Batching every question for a resource into one request is the
  obvious next step.
- Rate limits on the TypeSafe side change without notice. The SDK retries with backoff.
