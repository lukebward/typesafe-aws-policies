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

Requires Python 3.10+, `uv`, and the Pulumi CLI, with your usual Pulumi backend
and AWS credentials configured. Set `TYPESAFE_API_KEY` in your shell using a key
from the [TypeSafe console](https://console.typesafe.ai/).

One-time setup from the repository root:

```sh
uv venv venv
uv pip install --python venv/bin/python -r requirements.txt -r examples/demo/requirements.txt
pulumi -C examples/demo stack select dev --create
```

Preview:

```sh
pulumi -C examples/demo preview --policy-pack ../..
```

This uses your existing shell environment and previews six resources: two EC2
instances, two ingress rules, and two IAM policies. Nothing is deployed.

Expect three findings: `reconciliation`, `staff-portal`, and `metrics-reader`.
Preview should finish successfully with three advisory findings. The other
three resources should pass. Model judgments can vary.

## Tests

From the repository root after setup:

```sh
venv/bin/python -m pytest -q
RUN_LIVE=1 venv/bin/python -m pytest -q -s -k live
```

Offline tests need no API key. Live tests use your exported `TYPESAFE_API_KEY`.

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
