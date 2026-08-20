# CKV_AWS_366: Ensure AWS Cognito identity pool does not allow unauthenticated guest access

## Severity
**MEDIUM** (score: 5.0/10)

Allowing unauthenticated identities lets any unauthenticated internet user obtain temporary AWS credentials for the pool's guest IAM role, a known real-world root cause of anonymous data read/write and privilege-escalation incidents when that role carries any meaningful permissions.

## Summary
This check ensures that an Amazon Cognito identity pool does not have `allow_unauthenticated_identities` (Terraform) / `AllowUnauthenticatedIdentities` (CloudFormation) set to `true`, preventing anonymous/guest users from obtaining temporary AWS credentials.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **IaC frameworks:** CloudFormation, Terraform
- **Check type:** resource check
- **Entities:** `AWS::Cognito::IdentityPool` (property `AllowUnauthenticatedIdentities`), `aws_cognito_identity_pool` (attribute `allow_unauthenticated_identities`)

## Why it matters
Cognito identity pools are a common mechanism for issuing temporary, scoped IAM credentials to mobile/web app users via role assumption (through Cognito's "unauthenticated role" or "authenticated role"). If `allow_unauthenticated_identities` is enabled, **anyone** who can reach your app (no login required) can request an identity and receive temporary AWS credentials mapped to the pool's unauthenticated IAM role. This has repeatedly been the root cause of real-world incidents: over-permissioned unauthenticated roles (e.g., broad S3, DynamoDB, or Cognito admin permissions) have let anonymous internet users read/write data, enumerate resources, or escalate privileges — because developers assumed "unauthenticated" meant "low risk" and attached the same broad permissions used elsewhere. Disabling unauthenticated identities removes this entire anonymous-credential attack surface unless your application specifically requires guest functionality (and even then, the associated IAM role should be scoped extremely narrowly).

## How Checkov evaluates this
Attribute-value check (`BaseResourceValueCheck`) expecting `allow_unauthenticated_identities` / `AllowUnauthenticatedIdentities` to equal `False`. In the CloudFormation implementation, if the property block is entirely missing, the check explicitly **FAILS** (`missing_block_result=CheckResult.FAILED`) rather than passing by omission. In the Terraform implementation there's no explicit `missing_block_result` override, so Checkov's default handling for a missing attribute against a boolean expected value applies (an absent value is treated as not matching `False`, generally resulting in FAILED as well, consistent with AWS's default where the identity pool provider must actually be configured explicitly).

## Non-compliant example
```hcl
resource "aws_cognito_identity_pool" "app_pool" {
  identity_pool_name               = "app-identity-pool"
  allow_unauthenticated_identities = true

  cognito_identity_providers {
    client_id     = aws_cognito_user_pool_client.app_client.id
    provider_name = aws_cognito_user_pool.app_pool.endpoint
  }
}
```

## Remediated example
```hcl
resource "aws_cognito_identity_pool" "app_pool" {
  identity_pool_name               = "app-identity-pool"
  allow_unauthenticated_identities = false

  cognito_identity_providers {
    client_id     = aws_cognito_user_pool_client.app_client.id
    provider_name = aws_cognito_user_pool.app_pool.endpoint
  }
}
```

## Remediation steps
1. Set `allow_unauthenticated_identities = false` (Terraform) or `AllowUnauthenticatedIdentities: false` (CloudFormation) unless your application has a genuine, deliberate need for anonymous guest access.
2. If guest access is genuinely required, keep it enabled but audit the IAM role attached via `aws_cognito_identity_pool_roles_attachment` for the `unauthenticated` role — apply strict least-privilege scoping (e.g., read-only access to a single public S3 prefix, not broad service access).
3. Review CloudTrail/Cognito logs for existing unauthenticated identity usage before disabling, to confirm no legitimate guest flow silently depends on it.
4. This change can be applied without replacing the identity pool, but will break any client flow that currently relies on unauthenticated identities — test in a staging environment first.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/CognitoUnauthenticatedIdentities.py
- Checkov check source (CloudFormation): https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/CognitoUnauthenticatedIdentities.py
- AWS docs: https://docs.aws.amazon.com/cognito/latest/developerguide/identity-pools.html
