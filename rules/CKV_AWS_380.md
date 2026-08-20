# CKV_AWS_380: Ensure AWS Transfer Server uses latest Security Policy

## Severity
**MEDIUM** (score: 5.0/10)

Using an outdated AWS Transfer Family security policy can permit weaker/deprecated TLS ciphers and protocol versions, weakening transport security without disabling encryption outright.

## Summary
This check ensures an AWS Transfer Family server (`aws_transfer_server`) uses a security policy that is no more than 24 months old, rather than defaulting to an outdated TLS/SSH cipher policy.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `aws_transfer_server`

## Why it matters
AWS Transfer Family (SFTP/FTPS/FTP) servers use a named `security_policy_name` (e.g., `TransferSecurityPolicy-2018-11`, `TransferSecurityPolicy-2024-01`) that determines the set of allowed TLS/SSH protocol versions and cipher suites for client connections. Older security policies:

- Permit weaker, deprecated ciphers and protocol versions (e.g., older TLS versions, weaker key exchange algorithms) that are more susceptible to known cryptographic attacks (e.g., protocol downgrade attacks, weak cipher exploitation).
- Do not get the benefit of newer, hardened cipher suite defaults that AWS periodically introduces as older algorithms are deprecated industry-wide.

If `security_policy_name` is not set at all, Transfer Family defaults to `TransferSecurityPolicy-2018-11`, which by 2026 standards is stale and included some ciphers considered legacy in the initial release period.

## How Checkov evaluates this
The check parses `security_policy_name`, which is expected to embed a `YYYY-MM` date somewhere in its hyphen-delimited string (e.g., `TransferSecurityPolicy-2023-05`). It:

1. Splits the string on `-` and scans consecutive part pairs, trying to construct a valid `datetime(year, month, 1)`.
2. Compares that policy date to the current date and computes the difference in months.
3. If the difference is **less than 24 months**, the check **PASSES**.
4. If the policy is 24+ months old, or if `security_policy_name` is not set at all (defaulting to the old `2018-11` policy), the check **FAILS**.

## Non-compliant example
```hcl
resource "aws_transfer_server" "example" {
  identity_provider_type = "SERVICE_MANAGED"
  protocols              = ["SFTP"]
  security_policy_name   = "TransferSecurityPolicy-2018-11"
}
```

## Remediated example
```hcl
resource "aws_transfer_server" "example" {
  identity_provider_type = "SERVICE_MANAGED"
  protocols              = ["SFTP"]
  security_policy_name   = "TransferSecurityPolicy-2024-01"
}
```

## Remediation steps
1. Explicitly set `security_policy_name` to the most recent policy AWS Transfer Family offers (check the AWS provider/API docs for the current list, since AWS periodically releases new dated policies).
2. Periodically re-check and bump this value — since the check is time-relative (24-month rolling window), a policy that passes today will eventually fail again as it ages; treat this as a recurring maintenance item, not a one-time fix.
3. Verify client compatibility before upgrading: legacy SFTP/FTPS clients relying on older cipher suites may need updating alongside the server-side policy change.
4. This attribute can typically be updated in place without server downtime, but validate against your AWS provider version's behavior, since some historical provider versions required more careful handling of Transfer Family updates.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/TransferServerLatestPolicy.py)
- [AWS Transfer Family security policies documentation](https://docs.aws.amazon.com/transfer/latest/userguide/security-policies.html)
