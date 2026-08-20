# CKV_ALI_43: Ensure MongoDB instance is not public
## Severity
**CRITICAL** (score: 9.1/10)

A MongoDB instance whitelisting 0.0.0.0/0 is directly reachable from the entire internet, exposing a database service to unauthenticated network access and brute-force/exploit attempts.

## Summary
This check ensures that an Alibaba Cloud ApsaraDB for MongoDB instance's IP whitelist does not include `0.0.0.0` or `0.0.0.0/0`, which would allow connections from any address on the internet.

## Applicability
- **Framework:** Terraform
- **Resource type:** `alicloud_mongodb_instance`

## Why it matters
A database whitelist containing `0.0.0.0/0` removes network-level access control entirely, exposing the MongoDB instance's listener port directly to the public internet. Internet-facing, unauthenticated or weakly-authenticated MongoDB instances have historically been one of the most exploited misconfigurations in cloud security — mass-scanning campaigns and ransomware operators routinely discover and wipe/ransom exposed MongoDB deployments within hours of exposure. Even with authentication enabled, an open whitelist removes an entire layer of defense-in-depth, exposing the instance to brute-force credential attacks, unpatched-vulnerability exploitation, and denial-of-service from any internet host — none of which is possible if network access is restricted to known, trusted CIDR ranges.

## How Checkov evaluates this
This is a custom Python `BaseResourceCheck` that reads the `security_ip_list` attribute of `alicloud_mongodb_instance`.
- The check takes the first list of security IP entries (`security_ip_list[0]`) and checks whether it contains the literal string `"0.0.0.0"` or `"0.0.0.0/0"`.
- **FAIL** if either of those values is present in the list.
- **PASS** if `security_ip_list` is unset, or does not include the open/all-hosts entries.

## Non-compliant example
```hcl
resource "alicloud_mongodb_instance" "example" {
  engine_version      = "4.4"
  db_instance_class   = "mdb.shard.2x.large"
  db_instance_storage = 20
  network_type        = "VPC"
  vswitch_id          = alicloud_vswitch.example.id

  security_ip_list = ["0.0.0.0/0"]  # open to the entire internet
}
```

## Remediated example
```hcl
resource "alicloud_mongodb_instance" "example" {
  engine_version      = "4.4"
  db_instance_class   = "mdb.shard.2x.large"
  db_instance_storage = 20
  network_type        = "VPC"
  vswitch_id          = alicloud_vswitch.example.id

  security_ip_list = ["10.0.1.0/24", "10.0.2.15/32"]  # <-- scoped to trusted app-tier CIDR ranges
}
```

## Remediation steps
1. Replace any `0.0.0.0` / `0.0.0.0/0` entries in `security_ip_list` with the specific CIDR ranges of trusted application servers, bastion hosts, or VPN gateways.
2. If broad access is genuinely required (e.g., for a SaaS integration), prefer routing through a controlled proxy/bastion rather than whitelisting the entire internet.
3. Combine with `network_type = "VPC"` (CKV_ALI_41) so the instance is also not reachable via the legacy Classic network.
4. Audit application connection strings after tightening the whitelist to confirm no legitimate client is inadvertently blocked.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/alicloud/MongoDBIsPublic.py)
