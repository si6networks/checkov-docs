# CKV_SECRET_2: AWS Access Key

## Severity
**HIGH** (score: 7.5/10)

A leaked AWS access key is a long-lived static credential that can grant full programmatic account access up to administrator level, routinely harvested by bots within minutes of a public commit for account takeover or cryptomining abuse.

## Summary
This check scans file contents for hardcoded AWS access key IDs (and, in context, their paired secret access keys), flagging static AWS credentials committed directly into source or config files.

## Applicability
- **IaC/file type**: `secrets` — Checkov's regex/entropy-based secrets scanner, applied to any scanned file (Terraform `.tf`/`.tfvars`, YAML/JSON config, `.env` files, scripts, CI pipeline definitions, etc.), not limited to a single IaC resource type.
- **Entities**: the matched credential string within a file; findings are reported at the file/line level rather than against a graph resource.

## Why it matters
AWS access keys are long-lived, static IAM credentials that, once obtained, grant an attacker programmatic access to your AWS account with whatever permissions the associated IAM identity holds — potentially full account takeover if attached to an administrator or broadly-permissioned role/user. Public GitHub repositories are continuously scraped by automated bots that harvest AWS keys within minutes of a push, commonly used to spin up cryptocurrency-mining EC2 fleets at the victim's expense, exfiltrate S3 data, or pivot laterally through the account. Because the key is static (not time-bound like STS-issued temporary credentials), the exposure window is unlimited until someone notices and manually deactivates it — which is why AWS itself runs automated scanning of public repos and will proactively quarantine detected leaked keys.

## How Checkov evaluates this
The secrets scanner matches the well-known AWS access key ID format — a 20-character string beginning with a recognizable prefix (e.g. `AKIA`, `ASIA` for STS temporary keys, or other AWS-reserved prefixes) followed by uppercase alphanumeric characters — anywhere in scanned file content. When found, it is reported as a FAIL at that location; associated `aws_secret_access_key`-style values near a matched key increase confidence but the access-key-ID pattern alone is sufficient to trigger. As with other secrets checks, there is no "configuration" to evaluate — pass/fail is purely presence/absence of the matched pattern in the file.

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
  # Credentials sourced from environment variables, shared credentials file,
  # or an assumed IAM role — never hardcoded.
}
```

## Remediation steps
1. Treat any committed AWS key as compromised: deactivate and delete it immediately in IAM, and audit CloudTrail for unauthorized activity from that key.
2. Remove the hardcoded `access_key`/`secret_key` (or equivalent SDK config) from the file entirely.
3. Use one of AWS's supported credential-resolution mechanisms instead: environment variables, the shared `~/.aws/credentials` file (outside version control), an IAM instance profile/role, IRSA for EKS, or an assumed role via `aws sts assume-role`.
4. Purge the key from git history if it was ever pushed.
5. Enable IAM Access Analyzer / GuardDuty and configure billing alerts as a backstop against undetected key leaks.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/common/bridgecrew/integration_features/features/policy_metadata_integration.py)
- [AWS: Best practices for managing AWS access keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
