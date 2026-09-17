import json

import pulumi_aws as aws

aws.ec2.Instance("reconciliation",
    ami="ami-0abcdef1234567890", instance_type="t3.micro", associate_public_ip_address=True,
    tags={"purpose": "Finance staff reconcile invoices over the company VPN"})
aws.ec2.Instance("checkout",
    ami="ami-0abcdef1234567890", instance_type="t3.micro", associate_public_ip_address=True,
    tags={"purpose": "Shoppers browse products and pay from their own devices"})

aws.vpc.SecurityGroupIngressRule("staff-portal",
    security_group_id="sg-0123456789abcdef0", ip_protocol="tcp", from_port=443, to_port=443,
    cidr_ipv4="0.0.0.0/0", description="TLS access restricted to staff connected through the company VPN")
aws.vpc.SecurityGroupIngressRule("storefront",
    security_group_id="sg-0123456789abcdef0", ip_protocol="tcp", from_port=443, to_port=443,
    cidr_ipv4="0.0.0.0/0", description="TLS access for shoppers connecting from anywhere on the internet")

aws.iam.Policy("metrics-reader",
    description="Read CloudWatch metrics for the operations dashboard",
    policy=json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["cloudwatch:*", "ec2:*"], "Resource": "*"},
    ]}))
aws.iam.Policy("metrics-viewer",
    description="Read CloudWatch metrics for the operations dashboard",
    policy=json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["cloudwatch:GetMetricData", "cloudwatch:ListMetrics"], "Resource": "*"},
    ]}))
