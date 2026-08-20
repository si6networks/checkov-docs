# CKV_ALI_20: Ensure RDS instance uses SSL
## Severity
**HIGH** (score: 7.5/10)

Disabling SSL on an RDS instance allows database traffic to travel unencrypted, exposing credentials and sensitive query/result data to interception or manipulation in transit.

## Summary
This check verifies that an Alibaba Cloud ApsaraDB RDS instance has SSL encryption for client connections enabled or actively being configured.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `alicloud_db_instance`

## Why it matters
Without SSL/TLS on the database connection, all traffic between application clients and the RDS instance — including the authentication handshake and every query and result set — travels in plaintext over the network. An attacker with access to the network path (compromised host on the same VPC, misconfigured routing, a malicious insider, or a man-in-the-middle position) can passively sniff credentials and sensitive data, or actively tamper with queries/results. Enforcing SSL closes this exposure and is a standard requirement for handling regulated data (PCI-DSS, HIPAA, GDPR) in transit.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` inspecting the `ssl_action` attribute on `alicloud_db_instance`:
- Expected values are `"Open"` (SSL encryption enabled) or `"Update"` (an update to the SSL configuration is being applied, treated as acceptable/in-progress).
- Any other value — most notably `"Close"` or the attribute being absent — FAILS.

## Non-compliant example
```hcl
resource "alicloud_db_instance" "example" {
  engine           = "MySQL"
  engine_version   = "8.0"
  instance_type    = "rds.mysql.s1.small"
  instance_storage = "20"
  vswitch_id       = "vsw-example"
  ssl_action       = "Close"   # <-- fails: SSL not enforced on connections
}
```

## Remediated example
```hcl
resource "alicloud_db_instance" "example" {
  engine           = "MySQL"
  engine_version   = "8.0"
  instance_type    = "rds.mysql.s1.small"
  instance_storage = "20"
  vswitch_id       = "vsw-example"
  ssl_action       = "Open"    # <-- fix: SSL encryption enabled
}
```

## Remediation steps
1. Locate the `alicloud_db_instance` resource(s) missing or with `ssl_action` set to `"Close"`.
2. Set `ssl_action = "Open"` (or `"Update"` if you are actively rotating SSL settings) so the RDS instance enforces SSL on client connections.
3. Update application/client connection strings to use SSL/TLS (e.g. specify `sslmode=require` or the equivalent driver parameter, and reference the required CA certificate downloaded from the Alibaba Cloud console).
4. Enabling SSL is generally an in-place configuration change but may briefly interrupt existing non-SSL client connections — test in a non-production environment first.
5. Consider also enforcing SSL-only connections at the account/user grant level within the database engine itself.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/alicloud/RDSInstanceSSL.py)
- [Alibaba Cloud RDS instance resource docs](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/db_instance)
