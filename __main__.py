import json

from pulumi_policy import EnforcementLevel, PolicyPack, ResourceValidationPolicy
from typesafe_sdk import Noul, TypeSafeClient


def probability(args, question, **facts):
    state = {"name": args.name, "tags": dict(args.props.get("tags") or {}),
             "description": args.props.get("description"), **facts}
    with TypeSafeClient() as client:
        response = client.system_one(state=state, questions={"q": Noul(instructions=question)})
    return response.nouls["q"].noul


def internal_resource_not_public(args, report):
    if args.resource_type != "aws:ec2/instance:Instance":
        return
    if args.props.get("associatePublicIpAddress") is not True:
        return
    p = probability(args,
        "Do `name` or `tags` describe a component intended only for staff or private "
        "workflows, rather than a service intended for people on the internet?")
    if p >= 0.8:
        report(f"'{args.name}' looks internal but requests a public IP (p={p:.2f}).")


def sg_rule_matches_description(args, report):
    if args.resource_type != "aws:vpc/securityGroupIngressRule:SecurityGroupIngressRule":
        return
    props = args.props
    if props.get("cidrIpv4") != "0.0.0.0/0" and props.get("cidrIpv6") != "::/0":
        return
    if not props.get("description"):
        report(f"'{args.name}' allows traffic from anywhere but has no description.")
        return
    p = probability(args,
        "Does this ingress rule allow more access than `description` claims? "
        "Compare the stated audience and traffic with `source_is_anywhere`, "
        "`protocol`, and `ports`. A claim of staff-only or VPN-only access conflicts "
        "with an unrestricted source, even when the port matches.",
        source_is_anywhere=True, protocol=props.get("ipProtocol"),
        ports=[props.get("fromPort"), props.get("toPort")])
    if p >= 0.8:
        report(f"'{args.name}' allows more access than its description claims (p={p:.2f}).")


def iam_grant_matches_stated_purpose(args, report):
    if args.resource_type != "aws:iam/policy:Policy":
        return
    statements = json.loads(args.props.get("policy") or "{}").get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    if not any(s.get("Effect") == "Allow" for s in statements):
        return
    p = probability(args,
        "Do the permissions declared in `statements` substantially exceed the purpose "
        "stated in `name`, `description`, and `tags`? Look for unrelated services or "
        "write/admin capabilities for a read-only purpose. Consider the listed resources, "
        "conditions, and deny statements. A Resource wildcard alone is not a mismatch.",
        statements=statements)
    if p >= 0.8:
        report(f"'{args.name}' grants permissions beyond its stated purpose (p={p:.2f}).")


POLICIES = [
    ResourceValidationPolicy(
        name="internal-resource-not-public",
        description="Internal EC2 instances should not request a public IP.",
        enforcement_level=EnforcementLevel.ADVISORY,
        validate=internal_resource_not_public,
    ),
    ResourceValidationPolicy(
        name="sg-rule-matches-description",
        description="Public ingress should match its stated audience and traffic.",
        enforcement_level=EnforcementLevel.ADVISORY,
        validate=sg_rule_matches_description,
    ),
    ResourceValidationPolicy(
        name="iam-grant-matches-stated-purpose",
        description="IAM permissions should match the policy's stated purpose.",
        enforcement_level=EnforcementLevel.ADVISORY,
        validate=iam_grant_matches_stated_purpose,
    ),
]

if __name__ == "__main__":
    PolicyPack(name="typesafe-aws-policies", policies=POLICIES)
