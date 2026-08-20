# CKV_ALI_9: Ensure database instance is not public
## Severity
**CRITICAL** (score: 9.1/10)

An RDS instance whitelisting 0.0.0.0/0 is reachable from the entire internet, exposing a relational database directly to unauthenticated network-based attacks.

## Summary
This check ensures that an Alibaba Cloud RDS database instance's IP whitelist (`security_ips`) does not include `0.0.0.0` or `0.0.0.0/0`, which would allow connections from any address on the internet.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource type:** `alicloud_db_instance`

## Why it matters
Alibaba Cloud RDS instances use an IP whitelist (`security_ips`) as the primary network access control gating who can even attempt to connect to the database. Setting this to `0.0.0.0/0` (or the bare `0.0.0.0`) removes that control entirely, exposing the database's listener port directly to the internet. Internet-exposed relational databases are a routine target for mass scanning and automated exploitation — attackers probe for default credentials, known CVEs in the database engine, and weak authentication, and a successful compromise can lead to full data exfiltration, ransomware-style data destruction, or use of the database server as a pivot point into the rest of the environment. Restricting `security_ips` to known application-tier or VPN CIDR ranges eliminates this entire class of exposure, independent of how strong the database's own authentication is.

## How Checkov evaluates this
This is a custom Python `BaseResourceCheck` that reads the `security_ips` attribute of `alicloud_db_instance`.
- The check takes the first list of security IP entries (`security_ips[0]`) and checks whether it contains the literal string `"0.0.0.0"` or `"0.0.0.0/0"`.
- **FAIL** if either of those values is present.
- **PASS** if `security_ips` is unset, or does not include the open/all-hosts entries.

Note: despite the resource being a database, this check is tagged under the `ENCRYPTION` category in the Checkov source, but its actual logic is a network-exposure check, not an encryption check.

## Non-compliant example
```hcl
resource "alicloud_db_instance" "example" {
  engine           = "MySQL"
  engine_version    = "8.0"
  instance_type     = "rds.mysql.s2.large"
  instance_storage  = "20"

  security_ips = ["0.0.0.0/0"]  # open to the entire internet
}
```

## Remediated example
```hcl
resource "alicloud_db_instance" "example" {
  engine           = "MySQL"
  engine_version    = "8.0"
  instance_type     = "rds.mysql.s2.large"
  instance_storage  = "20"

  security_ips = ["10.0.1.0/24", "10.0.2.15/32"]  # <-- scoped to trusted application-tier CIDR ranges
}
```

## Remediation steps
1. Replace any `0.0.0.0` / `0.0.0.0/0` entries in `security_ips` with the specific CIDR ranges of trusted application servers, bastion hosts, or VPN gateways.
2. If wide access is needed for legitimate operational reasons, route through a bastion/proxy rather than opening the database to the entire internet.
3. Verify the instance is also deployed inside a VPC (rather than the legacy Classic network) for additional network-layer isolation.
4. After tightening `security_ips`, validate application connectivity to avoid accidentally locking out legitimate clients.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/alicloud/RDSIsPublic.py)
