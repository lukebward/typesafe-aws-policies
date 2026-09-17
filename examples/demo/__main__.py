"""Demo stack: one compliant and one violating resource per policy in typesafe-aws-policies."""
import json

import pulumi
import pulumi_aws as aws

GOOD_TAGS = {"owner": "platform-team", "env": "dev"}
PROD_TAGS = {"owner": "payments-team", "env": "prod"}


def doc(*statements):
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)})


# s3-bucket-policy-not-public
aws.s3.Bucket("public-assets", bucket="typesafe-demo-public-assets", tags=GOOD_TAGS)
aws.s3.BucketPolicy("public-assets-open-policy", bucket="typesafe-demo-public-assets",
    policy=doc({"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::typesafe-demo-public-assets/*"}))
aws.s3.Bucket("org-reports", bucket="typesafe-demo-org-reports", tags=GOOD_TAGS)
aws.s3.BucketPolicy("org-reports-policy", bucket="typesafe-demo-org-reports",
    policy=doc({"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::typesafe-demo-org-reports/*",
                "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-example123"}}}))

# s3-sensitive-bucket-encrypted, tags-owner-is-real, tags-env-recognized, resource-name-descriptive
aws.s3.Bucket("customer-pii-exports", tags={"owner": "todo", "env": "banana"})
aws.s3.Bucket("test123", tags=GOOD_TAGS)

# iam-no-admin-equivalent, iam-mutating-actions-scoped
aws.iam.Policy("ci-deployer", tags=GOOD_TAGS,
    policy=doc({"Effect": "Allow", "Action": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"], "Resource": "*"}))
aws.iam.Policy("instance-reaper", tags=GOOD_TAGS,
    policy=doc({"Effect": "Allow", "Action": ["ec2:TerminateInstances"], "Resource": "*"}))
aws.iam.Policy("inventory-reader", tags=GOOD_TAGS,
    policy=doc({"Effect": "Allow", "Action": ["ec2:Describe*", "s3:ListAllMyBuckets"], "Resource": "*"}))

# iam-trust-policy-restricted
aws.iam.Role("anyone-can-assume", tags=GOOD_TAGS,
    assume_role_policy=doc({"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}))
lambda_role = aws.iam.Role("order-processor-role", tags=GOOD_TAGS,
    assume_role_policy=doc({"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}))

# iam-no-service-users
aws.iam.User("ci-deploy-bot", tags=GOOD_TAGS)
aws.iam.User("jane-doe", name="jane.doe", tags=GOOD_TAGS)

# sg-no-public-admin-ports, sg-description-meaningful
aws.ec2.SecurityGroup("bastion-sg", description="Managed by Pulumi", tags=GOOD_TAGS,
    ingress=[{"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}])
aws.ec2.SecurityGroup("public-web-sg", description="Allows HTTPS from the internet to the public web tier", tags=GOOD_TAGS,
    ingress=[{"from_port": 443, "to_port": 443, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}])

# ec2-no-public-ip-in-prod
aws.ec2.Instance("checkout-api", ami="ami-0abcdef1234567890", instance_type="t3.micro", associate_public_ip_address=True, tags=PROD_TAGS)
aws.ec2.Instance("dev-scratch-box", ami="ami-0abcdef1234567890", instance_type="t3.micro", associate_public_ip_address=True, tags=GOOD_TAGS)

# rds-prod-not-public, rds-prod-backups-and-protection
aws.rds.Instance("orders-db", engine="postgres", instance_class="db.t3.micro", allocated_storage=20, username="app",
    manage_master_user_password=True, publicly_accessible=True, backup_retention_period=1, deletion_protection=False, tags=PROD_TAGS)
aws.rds.Instance("orders-db-hardened", engine="postgres", instance_class="db.t3.micro", allocated_storage=20, username="app",
    manage_master_user_password=True, publicly_accessible=False, backup_retention_period=7, deletion_protection=True, tags=PROD_TAGS)

# lambda-no-plaintext-secrets
code = pulumi.AssetArchive({"index.py": pulumi.StringAsset("def handler(event, context):\n    return 'ok'\n")})
aws.lambda_.Function("payment-webhook", role=lambda_role.arn, runtime="python3.12", handler="index.handler", code=code, tags=GOOD_TAGS,
    environment={"variables": {"STRIPE_SECRET_KEY": "sk-live-4eC39HqLyjWDarjtT1zdp7dc", "LOG_LEVEL": "info"}})
aws.lambda_.Function("order-processor", role=lambda_role.arn, runtime="python3.12", handler="index.handler", code=code, tags=GOOD_TAGS,
    environment={"variables": {"LOG_LEVEL": "info", "ORDERS_API_URL": "https://orders.internal.example.com"}})
