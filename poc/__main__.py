from pulumi_policy import EnforcementLevel, PolicyPack, ResourceValidationPolicy
from typesafe_sdk import Noul, TypeSafeClient


def probability(args, question):
    state = {"name": args.name, "tags": dict(args.props.get("tags") or {})}
    with TypeSafeClient() as client:
        response = client.system_one(state=state, questions={"q": Noul(instructions=question)})
    return response.nouls["q"].noul


def internal_resource_not_public(args, report):
    if args.resource_type != "aws:ec2/instance:Instance":
        return
    if args.props.get("associatePublicIpAddress") is not True:
        return
    p = probability(args,
        "Do `name` or `tags` identify an internal component, such as an admin console, "
        "back-office service, or worker, rather than a public-facing website or API?")
    if p >= 0.8:
        report(f"'{args.name}' looks internal but requests a public IP (p={p:.2f}).")


def log_and_temp_buckets_have_lifecycle(args, report):
    if args.resource_type != "aws:s3/bucket:Bucket":
        return
    if args.props.get("lifecycleRules"):
        return
    p = probability(args,
        "Do `name` or `tags` indicate logs, exports, scratch data, caches, or build "
        "artifacts that should expire, rather than durable uploads, documents, or backups?")
    if p >= 0.8:
        report(f"'{args.name}' looks temporary but has no lifecycle rules (p={p:.2f}).")


def sqs_work_queue_has_dlq(args, report):
    if args.resource_type != "aws:sqs/queue:Queue":
        return
    if args.props.get("redrivePolicy"):
        return
    p = probability(args,
        "Do `name` or `tags` identify a primary work queue for jobs, tasks, or order "
        "processing, rather than a dead-letter queue, retry queue, or notification sink?")
    if p >= 0.8:
        report(f"'{args.name}' looks like a work queue but has no dead-letter queue (p={p:.2f}).")


POLICIES = [
    ResourceValidationPolicy(
        name="internal-resource-not-public",
        description="Internal EC2 instances should not request a public IP.",
        enforcement_level=EnforcementLevel.ADVISORY,
        validate=internal_resource_not_public,
    ),
    ResourceValidationPolicy(
        name="log-and-temp-buckets-have-lifecycle",
        description="Log and temporary S3 buckets should have lifecycle rules.",
        enforcement_level=EnforcementLevel.ADVISORY,
        validate=log_and_temp_buckets_have_lifecycle,
    ),
    ResourceValidationPolicy(
        name="sqs-work-queue-has-dlq",
        description="SQS work queues should have a dead-letter queue.",
        enforcement_level=EnforcementLevel.ADVISORY,
        validate=sqs_work_queue_has_dlq,
    ),
]

if __name__ == "__main__":
    PolicyPack(name="typesafe-aws-policies", policies=POLICIES)
