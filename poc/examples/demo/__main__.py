import pulumi_aws as aws

aws.ec2.Instance("admin-console",
    ami="ami-0abcdef1234567890", instance_type="t3.micro",
    associate_public_ip_address=True)
aws.ec2.Instance("public-web",
    ami="ami-0abcdef1234567890", instance_type="t3.micro",
    associate_public_ip_address=True)

aws.s3.Bucket("access-logs")
aws.s3.Bucket("permanent-uploads")

aws.sqs.Queue("order-processing")
aws.sqs.Queue("order-processing-dlq")
