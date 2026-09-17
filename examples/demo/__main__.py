"""Demo stack: compliant and violating resources for each policy in typesafe-aws-policies."""
import json

import pulumi
import pulumi_aws as aws

GOOD_TAGS = {"owner": "platform-team", "env": "dev", "cost-center": "CC-4410"}
PROD_TAGS = {"owner": "payments-team", "env": "prod", "cost-center": "CC-2210"}
GITHUB_OIDC = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
SUBNETS = ["subnet-0123456789abcdef0", "subnet-0fedcba9876543210"]


def doc(*statements):
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)})


# 1 resource-policy-not-open: no condition (code), weak condition (model), strong condition (passes)
aws.s3.Bucket("public-assets", bucket="typesafe-demo-public-assets", tags=GOOD_TAGS)
aws.s3.BucketPolicy("public-assets-open-policy", bucket="typesafe-demo-public-assets",
    policy=doc({"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::typesafe-demo-public-assets/*"}))
aws.s3.Bucket("tls-only-assets", bucket="typesafe-demo-tls-only", tags=GOOD_TAGS)
aws.s3.BucketPolicy("tls-only-policy", bucket="typesafe-demo-tls-only",
    policy=doc({"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::typesafe-demo-tls-only/*",
                "Condition": {"Bool": {"aws:SecureTransport": "true"}}}))
aws.s3.Bucket("org-reports", bucket="typesafe-demo-org-reports", tags=GOOD_TAGS)
aws.s3.BucketPolicy("org-reports-policy", bucket="typesafe-demo-org-reports",
    policy=doc({"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::typesafe-demo-org-reports/*",
                "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-example123"}}}))

# 2 sensitive-data-store-encrypted, 3 prod-or-sensitive-store-protected (DynamoDB without SSE or PITR)
aws.dynamodb.Table("patient-records", attributes=[{"name": "id", "type": "S"}], hash_key="id", billing_mode="PAY_PER_REQUEST", tags=PROD_TAGS)
aws.ebs.Volume("ci-scratch", availability_zone="us-west-2a", size=8, encrypted=False, tags=GOOD_TAGS)

# 3 prod-or-sensitive-store-protected (RDS), 14 name-consistent-with-config
aws.rds.Instance("orders-db", engine="postgres", instance_class="db.t3.micro", allocated_storage=20, username="app",
    manage_master_user_password=True, storage_encrypted=True, backup_retention_period=1, deletion_protection=False, multi_az=False, tags=PROD_TAGS)
aws.rds.Instance("orders-db-hardened", engine="postgres", instance_class="db.t3.micro", allocated_storage=20, username="app",
    manage_master_user_password=True, storage_encrypted=True, backup_retention_period=7, deletion_protection=True, multi_az=True, tags=PROD_TAGS)
aws.rds.Instance("prod-reporting-db", engine="postgres", instance_class="db.t3.micro", allocated_storage=20, username="app",
    manage_master_user_password=True, storage_encrypted=True, backup_retention_period=7, deletion_protection=True, multi_az=True, tags=GOOD_TAGS)

# 4 iam-no-admin-equivalent, 5 iam-grant-matches-stated-purpose
aws.iam.Policy("ci-deployer", description="Deploy Lambda functions from CI", tags=GOOD_TAGS,
    policy=doc({"Effect": "Allow", "Action": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"], "Resource": "*"}))
aws.iam.Policy("read-metrics", description="Read CloudWatch metrics for the ops dashboard", tags=GOOD_TAGS,
    policy=doc({"Effect": "Allow", "Action": ["cloudwatch:*", "ec2:*"], "Resource": "*"}))
aws.iam.Policy("inventory-reader", description="List EC2 instances and buckets for the inventory report", tags=GOOD_TAGS,
    policy=doc({"Effect": "Allow", "Action": ["ec2:DescribeInstances", "s3:ListAllMyBuckets"], "Resource": "*"}))

# 6 iam-trust-policy-restricted
aws.iam.Role("anyone-can-assume", tags=GOOD_TAGS,
    assume_role_policy=doc({"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}))
aws.iam.Role("github-deploy-any-repo", tags=GOOD_TAGS,
    assume_role_policy=doc({"Effect": "Allow", "Principal": {"Federated": GITHUB_OIDC}, "Action": "sts:AssumeRoleWithWebIdentity",
                            "Condition": {"StringLike": {"token.actions.githubusercontent.com:sub": "repo:acme/*:*"}}}))
aws.iam.Role("github-deploy-shop-main", tags=GOOD_TAGS,
    assume_role_policy=doc({"Effect": "Allow", "Principal": {"Federated": GITHUB_OIDC}, "Action": "sts:AssumeRoleWithWebIdentity",
                            "Condition": {"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                                                           "token.actions.githubusercontent.com:sub": "repo:acme/shop:ref:refs/heads/main"}}}))
lambda_role = aws.iam.Role("order-processor-role", tags=GOOD_TAGS,
    assume_role_policy=doc({"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}))

# 7 iam-no-service-users
aws.iam.User("ci-deploy-bot", tags=GOOD_TAGS)
aws.iam.User("jane-doe", name="jane.doe", tags=GOOD_TAGS)

# 8 sg-rule-matches-description, 9 sg-description-meaningful
aws.ec2.SecurityGroup("bastion-sg", description="Managed by Pulumi", tags=GOOD_TAGS,
    ingress=[{"from_port": 0, "to_port": 65535, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"], "description": "HTTPS from the ALB"}])
aws.ec2.SecurityGroup("legacy-sg", description="Legacy access for the ops team over SSH", tags=GOOD_TAGS,
    ingress=[{"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}])
aws.ec2.SecurityGroup("public-web-sg", description="Allows HTTPS from the internet to the public web tier", tags=GOOD_TAGS,
    ingress=[{"from_port": 443, "to_port": 443, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"], "description": "Public HTTPS to the web tier"}])

# 10 internal-resource-not-public
aws.ec2.Instance("admin-console", ami="ami-0abcdef1234567890", instance_type="t3.micro", associate_public_ip_address=True, tags=GOOD_TAGS)
aws.ec2.Instance("public-web-1", ami="ami-0abcdef1234567890", instance_type="t3.micro", associate_public_ip_address=True, tags=GOOD_TAGS)
aws.lb.LoadBalancer("backoffice-api", load_balancer_type="application", internal=False, subnets=SUBNETS, tags=GOOD_TAGS)
aws.lb.LoadBalancer("public-web-alb", load_balancer_type="application", internal=False, subnets=SUBNETS, tags=GOOD_TAGS)

# 11 log-and-temp-buckets-have-lifecycle
aws.s3.Bucket("alb-access-logs", tags=GOOD_TAGS)
aws.s3.Bucket("customer-uploads", tags=GOOD_TAGS, versioning={"enabled": True}, server_side_encryption_configuration={"rule": {"apply_server_side_encryption_by_default": {"sse_algorithm": "AES256"}}})

# 12 no-plaintext-secrets-in-env
code = pulumi.AssetArchive({"index.py": pulumi.StringAsset("def handler(event, context):\n    return 'ok'\n")})
aws.lambda_.Function("payment-webhook", role=lambda_role.arn, runtime="python3.12", handler="index.handler", code=code, tags=GOOD_TAGS,
    environment={"variables": {"STRIPE_SECRET_KEY": "sk-live-4eC39HqLyjWDarjtT1zdp7dc", "LOG_LEVEL": "info"}})
aws.lambda_.Function("order-processor", role=lambda_role.arn, runtime="python3.12", handler="index.handler", code=code, tags=GOOD_TAGS,
    environment={"variables": {"LOG_LEVEL": "info", "ORDERS_API_URL": "https://orders.internal.example.com"}})
aws.ecs.TaskDefinition("api-task", family="api", tags=GOOD_TAGS,
    container_definitions=json.dumps([{"name": "api", "image": "acme/api:1.0", "memory": 512,
                                       "environment": [{"name": "DB_PASSWORD", "value": "Tr0ub4dor&3xyz"}, {"name": "PORT", "value": "8080"}]}]))

# 10 internal-resource-not-public (Lambda URL without auth)
aws.lambda_.Function("internal-report-generator", name="internal-report-generator", role=lambda_role.arn, runtime="python3.12",
    handler="index.handler", code=code, tags=GOOD_TAGS)
aws.lambda_.FunctionUrl("internal-report-url", function_name="internal-report-generator", authorization_type="NONE")

# 13 tags-meaningful, 2 and 3 for S3 (sensitive, unencrypted, unversioned)
aws.s3.Bucket("customer-pii-exports", tags={"owner": "todo", "env": "banana", "cost-center": "n/a"})

# 15 sqs-work-queue-has-dlq
aws.sqs.Queue("order-processing", tags=GOOD_TAGS)
aws.sqs.Queue("order-processing-dlq", tags=GOOD_TAGS)
