# TypeSafe AWS policies

A small Pulumi CrossGuard POC: **code checks the configuration, TypeSafe judges the intent.**
All three policies and the TypeSafe call live in [`__main__.py`](__main__.py).

| Policy | Python checks | TypeSafe asks |
| --- | --- | --- |
| Internal EC2 instances | Requests a public IP? | Does the name or tags suggest an internal component? |
| Security-group ingress | Source open to everyone? Extract protocol and ports. | Does that access exceed what the description claims? |
| IAM policy permissions | Parse statements; any Allow grants? | Do the grants substantially exceed the stated purpose? |

Each question returns the probability of yes. At `p >= 0.8`, Python reports a
finding. All three policies are advisory so the demo completes. Change a policy's
`enforcement_level` to `EnforcementLevel.MANDATORY` to block instead.
Read any validator top to bottom: field check → question → threshold → report.

The ambiguity is in the intended use. Both demo ingress rules allow TCP 443 from
anywhere, but one promises access restricted to staff on the company VPN while
the other describes an internet storefront. Both IAM policies claim to read
CloudWatch metrics, but one also grants write access and control over EC2.
Jev compares that prose with facts extracted by code. The EC2 examples likewise
use purpose tags describing staff workflows versus shoppers, not names like
`internal-server` and `public-server`.

## Try it

Requires Python 3.10+, `uv`, and the Pulumi CLI. **The live tests and demo also
require a TypeSafe API key.** Get a key from the [TypeSafe console](https://console.typesafe.ai/)
and export it as `TYPESAFE_API_KEY` in the shell where you run these commands.
The offline tests run without an API key.

From the repository root:

```sh
uv venv venv
uv pip install --python venv/bin/python -r requirements.txt
export TYPESAFE_API_KEY=your-key
venv/bin/python -m pytest -q
RUN_LIVE=1 venv/bin/python -m pytest -q -s -k live
```

The key stays in your environment. If you already keep it in the repository root’s
gitignored `.env`, load it with `set -a; source .env; set +a`.

## Preview the demo

Six resources: two EC2 instances, two ingress rules, and two IAM policies.
Each pair has one intended finding and one intended pass. Nothing is deployed; no AWS account is needed.
Run from the repository root after the setup above, with `TYPESAFE_API_KEY` still exported:

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

Expect three findings: `reconciliation`, `staff-portal`, and `metrics-reader`.
Preview should finish successfully with three advisory findings. The other
three resources should pass. Model judgments can vary.

## POC scope

This demonstrates intent checks, not comprehensive AWS security coverage. The
model sees logical names, tags, descriptions, and the relevant network facts or
IAM statements.

- EC2 checks explicit public-IP requests, not effective network reachability.
- Ingress checks standalone `aws.vpc.SecurityGroupIngressRule` resources whose
  source is `0.0.0.0/0` or `::/0`. Missing descriptions are reported without AI.
  Other CIDRs and inline security-group rules are outside this POC's scope.
- IAM checks JSON policy documents on `aws.iam.Policy`. It compares declared
  grants with stated purpose; it does not simulate effective AWS permissions.

Unknown preview inputs are deferred by Pulumi. The `0.8` threshold is
illustrative, not a calibrated production guarantee. Model judgments can vary.
