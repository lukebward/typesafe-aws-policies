# TypeSafe AWS policies — POC

A small Pulumi CrossGuard POC: **code checks the configuration, TypeSafe judges the intent.**
All three policies and the TypeSafe call live in [`__main__.py`](__main__.py).

| Policy | Python checks | TypeSafe asks |
| --- | --- | --- |
| Internal EC2 instances | Requests a public IP? | Does the name or tags suggest an internal component? |
| Temporary S3 buckets | Missing lifecycle rules? | Does the bucket hold data that should expire? |
| SQS work queues | Missing a dead-letter queue? | Is this a work queue rather than a DLQ? |

Each question returns the probability of yes. At `p >= 0.8`, Python reports a
finding. All three policies are advisory so the demo completes. Change a policy's
`enforcement_level` to `EnforcementLevel.MANDATORY` to block instead.
Read any validator top to bottom: field check → question → threshold → report.

## Try it

Requires Python 3.10+, `uv`, and the Pulumi CLI.

```sh
cd poc
uv venv venv
uv pip install --python venv/bin/python -r requirements.txt
export TYPESAFE_API_KEY=your-key
venv/bin/python -m pytest -q
RUN_LIVE=1 venv/bin/python -m pytest -q -s -k live
```

The key stays in your environment. If you already keep it in the repository root’s
gitignored `.env`, load it from `poc/` with
`set -a; source ../.env; set +a`.

## Preview the demo

Six resources: an internal and public EC2 instance, a temporary and durable
bucket, and a work queue and DLQ. Nothing is deployed; no AWS account is needed.
Run from `poc/` after the setup above:

```sh
cd examples/demo
uv venv venv
uv pip install --python venv/bin/python -r requirements.txt
mkdir -p .pulumi
export PULUMI_BACKEND_URL="file://$PWD/.pulumi"
export PULUMI_CONFIG_PASSPHRASE=demo
unset PULUMI_API PULUMI_ACCESS_TOKEN AWS_PROFILE AWS_SESSION_TOKEN
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test
pulumi stack select dev --create
pulumi preview --policy-pack ../..
```

Expect three findings: `admin-console`, `access-logs`, and `order-processing`.
Preview should finish successfully with three advisory findings. The other
three resources should pass. Model judgments can vary.

## POC scope

This demonstrates three checks, not comprehensive AWS security coverage. The
model sees only logical resource names and tags. EC2 checks an explicit public-IP
request, not effective network reachability. S3 checks for inline `lifecycleRules`
on `aws.s3.Bucket`, not their adequacy or separate lifecycle resources. SQS checks
whether `redrivePolicy` is present. Unknown preview inputs are deferred by Pulumi.
The `0.8` threshold is illustrative, not a calibrated production guarantee.

The [full policy pack](../README.md) remains available at the repository root.
