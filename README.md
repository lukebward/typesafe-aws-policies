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

# live tests against the real model
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

| Policy | Resources | Primitive | The question | Exact check in code |
| --- | --- | --- | --- | --- |
| s3-bucket-policy-not-public | s3 BucketPolicy | Noul | Does any Allow statement grant access to anonymous users or every principal without a limiting condition? | parse policy JSON |
| s3-sensitive-bucket-encrypted | s3 Bucket | Noul | Do the name or tags suggest sensitive data? | no server-side encryption configured |
| iam-no-admin-equivalent | iam Policy, RolePolicy | Noul | Do the permissions give full account control directly or via an escalation path? | parse policy JSON |
| iam-mutating-actions-scoped | iam Policy, RolePolicy | Noul | Do these actions create, change, or delete things? | Resource is `*` |
| iam-trust-policy-restricted | iam Role | Noul | Can every principal, or another account without a condition, assume the role? | parse trust policy |
| iam-no-service-users | iam User | Noul | Does the user name identify a machine or service rather than a person? | none |
| sg-no-public-admin-ports | ec2 SecurityGroup, SecurityGroupRule | Noul per rule | Does this port range expose an admin or database service? | rule is open to `0.0.0.0/0` or `::/0` |
| sg-description-meaningful | ec2 SecurityGroup | Score (3 levels) | How well does the description explain purpose and traffic? | score below 1 |
| ec2-no-public-ip-in-prod | ec2 Instance | Choice | Which environment does the env tag identify? | `associatePublicIpAddress` is true |
| rds-prod-not-public | rds Instance, Cluster | Choice | Which environment does the env tag identify? | `publiclyAccessible` is true |
| rds-prod-backups-and-protection | rds Instance, Cluster | Choice | Which environment does the env tag identify? | retention below 7 or no deletion protection |
| lambda-no-plaintext-secrets | lambda Function | Noul per variable | Given the name and value shape, is this a plaintext credential? | value shape computed in code; the value itself is never sent |
| tags-owner-is-real | any resource with tags | Noul | Is the owner tag a placeholder rather than a real team or person? | tag present |
| tags-env-recognized | any resource with tags | Choice | Which environment does the env tag identify? | violation on `unknown` or low confidence |
| resource-name-descriptive | any resource | Noul | Is the resource name a placeholder or throwaway? | skips `pulumi:` resources |

Security policies are MANDATORY. Hygiene policies (names, descriptions, tags, IAM users) are ADVISORY.

## Layout

- `judge.py` wraps the TypeSafe client: API key, in-process cache, shared env Choice, value-shape helper.
- `policies.py` holds the 15 validators and the `POLICIES` registry.
- `__main__.py` wires the registry into a `PolicyPack`.
- `test_policies.py` runs every policy against a fake client. `test_live.py` runs them against the real model.
- `examples/demo` is a stack with one compliant and one violating resource per policy.

## Notes

- One request per policy per resource. Batching all questions for a resource into one request is the obvious follow-up.
- Jev reads instructions literally and is weak at arithmetic, dates, and counting. Those checks stay in code.
- The dummy AWS keys satisfy the provider's credential chain; `aws:skipCredentialsValidation` in `Pulumi.dev.yaml` stops it from calling AWS.
- `s3-sensitive-bucket-encrypted` reads the inline `serverSideEncryptionConfiguration` input on `aws.s3.Bucket`. Stacks that use the separate `BucketServerSideEncryptionConfiguration` resource need a stack-level policy instead.
- Thresholds live in `judge.py` (`DEFAULT = 0.8`, `HIGH = 0.85`). Tune them on real previews.
