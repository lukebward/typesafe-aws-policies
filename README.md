# typesafe-aws-policies

A Pulumi CrossGuard policy pack where each policy is a plain-English question answered by
[TypeSafe](https://typesafe.ai)'s Jev model. Exact checks (CIDRs, booleans, numbers) stay in code.
The model only answers the part that is easy to say and hard to write as a rule.

Each policy sends a small JSON `state` and one or more typed questions (Noul, Choice, Score) to
TypeSafe. The answer comes back as a probability. Code applies a threshold and reports the violation.

## Run

```sh
uv venv venv --python 3.13
uv pip install --python venv/bin/python -r requirements.txt

# unit tests, no network
venv/bin/python -m pytest -q test_judge.py test_policies.py

# live tests against the real model (or put TYPESAFE_API_KEY=... in a .env next to judge.py; it is gitignored)
TYPESAFE_API_KEY=... venv/bin/python -m pytest -q test_live.py -s

# demo preview on the local file backend, no AWS credentials needed
cd examples/demo
uv venv venv --python 3.13 && uv pip install --python venv/bin/python -r requirements.txt
env -u PULUMI_API -u PULUMI_ACCESS_TOKEN -u AWS_PROFILE -u AWS_SESSION_TOKEN \
  PULUMI_BACKEND_URL=file://$PWD/.pulumi PULUMI_CONFIG_PASSPHRASE= \
  AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_EC2_METADATA_DISABLED=true \
  TYPESAFE_API_KEY=... \
  pulumi stack init dev 2>/dev/null; \
env -u PULUMI_API -u PULUMI_ACCESS_TOKEN -u AWS_PROFILE -u AWS_SESSION_TOKEN \
  PULUMI_BACKEND_URL=file://$PWD/.pulumi PULUMI_CONFIG_PASSPHRASE= \
  AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_EC2_METADATA_DISABLED=true \
  TYPESAFE_API_KEY=... \
  pulumi preview --stack dev --policy-pack ../..
```

## Policies

Code decides every case it can decide exactly. The model only gets the gray zone.

| Policy | Resources | Code decides | Model decides |
| --- | --- | --- | --- |
| resource-policy-not-open | S3, KMS, SQS, SNS, Secrets Manager policies | wildcard principal with no Condition is a violation outright | when a Condition exists: does it restrict who can call (PrincipalOrgID yes, SecureTransport no) |
| sensitive-data-store-encrypted | S3, RDS, DynamoDB, EBS, EFS | the per-type encryption field | do name, tags, description indicate sensitive data |
| prod-or-sensitive-store-protected | RDS, S3, DynamoDB | backups, deletion protection, multi-AZ, versioning, PITR | is this production, is this sensitive (one request, two questions) |
| iam-no-admin-equivalent | IAM policies | known escalation chains from an action catalog (PassRole plus compute, policy version edits, attach policy, create credentials), wildcards and NotAction included | whether an unlisted service wildcard, combined with PassRole, can run code under a passed role |
| iam-grant-matches-stated-purpose | IAM policies | none | Score: does the grant match the name and description, go somewhat beyond, or far beyond |
| iam-trust-policy-restricted | IAM roles (aws and aws-native) | `Principal: *` with no Condition outright; cross-account root trust without ExternalId, PrincipalArn, or org conditions when `ownAccountId` is configured; service principals and named roles skipped | federated subject breadth (OIDC `sub` wildcards like `repo:org/*:*`) and whether conditioned principals are really pinned |
| iam-trust-account-wide | IAM roles (aws and aws-native) | account-wide root trust without a restricting condition, unless the account is `ownAccountId` or in `trustedAccountIds` | none |
| iam-no-service-users | IAM users | none | does the user name identify a machine rather than a person |
| sg-rule-matches-description | security groups and ingress rules | rule is public or broad; missing description is a violation outright | does the rule allow substantially more than its description claims |
| sg-description-meaningful | security groups | none | Score on description quality |
| internal-resource-not-public | EC2, RDS, load balancers, Lambda URLs | the per-type public flag | do name, tags, description indicate an internal or admin component |
| log-and-temp-buckets-have-lifecycle | S3 | lifecycle rules present | is this bucket for logs, exports, scratch, or artifacts |
| no-plaintext-secrets-in-env | Lambda, ECS task definitions, CodeBuild | value shape computed locally, value never sent; secret-store references skipped | given name and shape, is this a plaintext credential |
| tags-meaningful | any resource with tags | which tags are present | owner is real, env is recognized, cost center is plausible (one request) |
| name-consistent-with-config | any resource with an env tag | env tag present | does the name imply a different environment than the tag |
| sqs-work-queue-has-dlq | SQS queues | redrive policy present | is this a primary work queue rather than a dead-letter or fan-out queue |

Security policies are MANDATORY. Hygiene policies (purpose fit, names, descriptions, tags, IAM users, lifecycle, DLQ, account-wide trust) are ADVISORY.

## Running against a real stack

```sh
# from the stack's project directory
pulumi preview --policy-pack ~/Workspace/Pulumi/typesafe-aws-policies \
  --policy-pack-config ~/Workspace/Pulumi/typesafe-aws-policies/examples/policy-config.example.json
```

- Set `ownAccountId` in the config to the stack's AWS account. Same-account root trust (`arn:aws:iam::<own>:root`) is a
  common, intentional pattern and is then accepted. Without it, such roles show as an advisory so nothing blocks.
- Inputs that are computed from other resources are unknown during a preview. Policies that need them mark themselves
  not applicable for that preview and evaluate on `pulumi up`, when the values are known.
- To start advisory-only across the pack, add `"all": {"enforcementLevel": "advisory"}` to the config file.
- A preview only prints violations. To see every verdict, passes included, audit the stack's state instead:

```sh
venv/bin/python audit.py --stack org/stack --config examples/policy-config.example.json
```

## Layout

- `judge.py` wraps the TypeSafe client: API key, in-process cache, shared env Choice, value-shape helper.
- `policies.py` holds the 15 validators and the `POLICIES` registry.
- `__main__.py` wires the registry into a `PolicyPack`.
- `audit.py` runs every policy over `pulumi stack export` output and prints each verdict.
- `test_policies.py` runs every policy against a fake client. `test_live.py` runs them against the real model.
- `examples/demo` is a stack with compliant and violating resources for each policy.

## Notes

- One request per policy per resource. Batching all questions for a resource into one request is the obvious follow-up.
- Jev reads instructions literally and is weak at arithmetic, dates, and counting. Those checks stay in code.
- The dummy AWS keys satisfy the provider's credential chain; `aws:skipCredentialsValidation` in `Pulumi.dev.yaml` stops it from calling AWS.
- The S3 checks read the inline `serverSideEncryptionConfiguration`, `versioning`, and `lifecycleRules` inputs on `aws.s3.Bucket`. Stacks that use the separate configuration resources need a stack-level policy instead.
- Thresholds live in `judge.py` (`DEFAULT = 0.8`, `HIGH = 0.85`). On the live run every intended violation scored 0.85 or higher and every intended pass scored 0.20 or lower.
- Give the model pre-digested facts, not raw JSON. Raw IAM statements scored 0.52 to 0.59 on escalation chains; the same cases scored 0.81 to 0.98 once code extracted the relevant actions and principal kinds.
