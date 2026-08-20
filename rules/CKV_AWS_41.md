# CKV_AWS_41: Ensure no hard coded AWS access key and secret key exists in provider
## Severity
**CRITICAL** (score: 9.5/10)

Hard-coded AWS access and secret keys committed in provider/function configuration are directly exploitable credentials that grant an attacker who reads the code or repository full programmatic access to the AWS account.

## Summary
This check scans the Terraform `aws` provider block (and Serverless Framework `provider.aws` functions) for hard-coded AWS access key IDs and secret access keys, which should never be committed to source control.

## Applicability
**Checkov framework(s):** `serverless`, `terraform`

- **Frameworks:** Terraform, Serverless Framework
- **Resource/entity types:**
  - Terraform: `aws` provider block (checks the `access_key` and `secret_key` arguments)
  - Serverless: `serverless_aws` function definitions (checks environment variables for values matching AWS key patterns)

## Why it matters
Static AWS credentials embedded directly in Terraform provider blocks or Serverless function environment variables end up committed to version control history — even if later removed, they remain retrievable from git history indefinitely unless history is rewritten. Leaked AWS access keys are one of the most common and highest-impact cloud security incidents: automated credential-scanning bots continuously scrape public (and sometimes private/leaked) repositories for AWS key patterns, and a live key can be used within minutes to spin up cryptomining infrastructure, exfiltrate data, or pivot further into an account. Hard-coded credentials also can't be rotated or scoped as easily as instance-profile/role-based credentials, and they bypass centralized secrets-management, auditing, and MFA-conditional-access controls.

## How Checkov evaluates this
- **Terraform provider check:** a `BaseProviderCheck` on the `aws` provider. It inspects the `access_key` and `secret_key` arguments; if either value is a string matching a regex pattern characteristic of AWS access key IDs (`access_key_pattern`, e.g. `AKIA...`) or secret keys (`secret_key_pattern`), the check **FAILS**. Absence of these arguments (i.e., relying on environment variables, instance profiles, or shared credentials files) → **PASS**.
- **Serverless check:** a `BaseFunctionCheck` on `serverless_aws` functions. It scans the function's `environment` variables (string values only) against the same `access_key_pattern`/`secret_key_pattern` regexes; a match on any variable → **FAILS**.

## Non-compliant example
```hcl
provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}
```

## Remediated example
```hcl
provider "aws" {
  region = "us-east-1"
  # No static credentials: rely on environment variables, an IAM role
  # (e.g. via EC2 instance profile / IRSA / OIDC), or the shared credentials file.
}
```

## Remediation steps
1. Remove any `access_key`/`secret_key` arguments from the `aws` provider block (and any hard-coded key-like strings from Serverless function environment variables).
2. Use one of the standard AWS credential-resolution mechanisms instead: environment variables (`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`) injected at runtime by your CI/CD system, an IAM role attached to the execution environment (EC2 instance profile, ECS task role, Lambda execution role, IRSA for EKS), or `~/.aws/credentials` with a named profile.
3. If a static key was ever committed, treat it as compromised: deactivate/delete it in IAM immediately and issue a new one — do not merely remove it from the file, since it remains in git history.
4. Prefer OIDC federation (e.g., GitHub Actions → AWS role assumption) over long-lived access keys for CI/CD pipelines entirely.
5. Add a pre-commit secret scanner (e.g., detect-secrets, gitleaks) to catch this before it reaches the repository.

## References
- [Checkov check source (Terraform provider)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/provider/aws/credentials.py)
- [Checkov check source (Serverless)](https://github.com/bridgecrewio/checkov/blob/main/checkov/serverless/checks/function/aws/AWSCredentials.py)
- [Terraform AWS provider authentication docs](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#authentication)
