"""typesafe-aws-policies: AWS good-usage rules where each rule is a question answered by TypeSafe's Jev model.

Publish from inside this directory (`pulumi policy publish`) so PulumiPolicy.yaml sits at the analyzer root.
"""
from pulumi_policy import PolicyPack, ResourceValidationPolicy

import policies

PolicyPack(
    name="typesafe-aws-policies",
    policies=[
        ResourceValidationPolicy(
            name=rule.name,
            description=rule.validate.__doc__.strip(),
            validate=rule.validate,
            enforcement_level=rule.enforcement,
            severity=rule.severity,
            config_schema=rule.config_schema,
        )
        for rule in policies.POLICIES
    ],
)
