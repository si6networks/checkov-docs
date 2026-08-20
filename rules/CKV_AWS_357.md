# CKV_AWS_357: Ensure Transfer Server allows only secure protocols
## Severity
**HIGH** (score: 7.5/10)

Allowing FTP on an AWS Transfer Family server permits authentication credentials and file contents to be transmitted in cleartext, exposing them to interception by anyone able to observe the network path.

## Summary
Ensures AWS Transfer Family servers do not enable plaintext FTP as one of their supported file-transfer protocols.

## Applicability
- **Framework**: Terraform
- **Resource type**: `aws_transfer_server`

## Why it matters
AWS Transfer Family supports SFTP, FTPS, and plain FTP as protocol options for the managed file-transfer endpoint. Plain FTP transmits both authentication credentials and file contents entirely in cleartext over the network — anyone able to observe the traffic path (a compromised on-path network device, a misconfigured VPC route, an attacker with access to a shared network segment) can trivially capture usernames, passwords, and the full content of any file transferred, with no cryptographic protection whatsoever. This is a legacy protocol carried forward largely for backward compatibility with old clients, and AWS itself notes FTP should only be used inside a VPC with tightly controlled network access as a last resort. Because a Transfer Server is often exposed to external partners/vendors for automated file exchange (which can include sensitive business data, PII, or financial files), allowing FTP creates a straightforward interception path for both credentials and data.

## How Checkov evaluates this
The check inspects the `protocols` attribute (a list):
- **FAIL**: `"FTP"` appears anywhere in the `protocols` list.
- **PASS**: `protocols` is absent, not a list, or is a list that does not contain `"FTP"` (e.g., only `SFTP` and/or `FTPS`).

Note that `FTPS` (FTP over explicit TLS) is treated as acceptable by this check — only literal unencrypted `FTP` triggers a failure.

## Non-compliant example
```hcl
resource "aws_transfer_server" "partner_transfer" {
  identity_provider_type = "SERVICE_MANAGED"
  protocols              = ["SFTP", "FTP"]   # FTP allows unencrypted transfers
  endpoint_type          = "VPC"

  endpoint_details {
    vpc_id     = aws_vpc.example.id
    subnet_ids = [aws_subnet.transfer.id]
  }
}
```

## Remediated example
```hcl
resource "aws_transfer_server" "partner_transfer" {
  identity_provider_type = "SERVICE_MANAGED"
  protocols              = ["SFTP", "FTPS"]   # FTP removed; only encrypted protocols allowed
  endpoint_type          = "VPC"
  certificate            = aws_acm_certificate.transfer.arn   # required when FTPS is enabled

  endpoint_details {
    vpc_id     = aws_vpc.example.id
    subnet_ids = [aws_subnet.transfer.id]
  }
}
```

## Remediation steps
1. Find all `aws_transfer_server` resources whose `protocols` list includes `"FTP"`.
2. Remove `"FTP"` from the list, keeping only `"SFTP"` and/or `"FTPS"` depending on what your client/partner ecosystem actually needs.
3. If you enable `"FTPS"`, you must also supply a valid `certificate` (ACM certificate ARN) for TLS termination, and typically an `endpoint_type = "VPC"` with appropriate DNS/certificate hostname alignment.
4. Coordinate with external partners/vendors who may currently connect via plain FTP — they will need to migrate their client configuration to SFTP or FTPS before you remove FTP support, to avoid breaking active integrations.
5. Consider disabling `identity_provider_type = "SERVICE_MANAGED"` in favor of a custom identity provider or AWS Directory Service integration if you also need finer-grained authentication controls alongside the protocol hardening.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/TransferServerAllowsOnlySecureProtocols.py
- AWS docs: https://docs.aws.amazon.com/transfer/latest/userguide/create-server-in-transfer-family.html
