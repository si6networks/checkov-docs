# CKV_ALI_42: Ensure Mongodb instance uses SSL
## Severity
**HIGH** (score: 7.5/10)

Without SSL enforced, MongoDB traffic including authentication credentials and query data travels in plaintext and is vulnerable to interception.

## Summary
This check ensures that an Alibaba Cloud ApsaraDB for MongoDB instance has SSL/TLS enabled (or being updated to a new certificate) for encrypting data in transit between clients and the database.

## Applicability
- **Framework:** Terraform
- **Resource type:** `alicloud_mongodb_instance`

## Why it matters
Without SSL/TLS enabled, traffic between application clients and the MongoDB instance travels in plaintext. Any party with visibility into the network path — a compromised host on the same VPC, a misconfigured routing setup, or an attacker who has achieved a man-in-the-middle position — can passively capture credentials, query contents, and returned documents, or actively tamper with traffic. Since MongoDB instances frequently store application data including PII, session tokens, or business-critical records, unencrypted transport directly undermines confidentiality and integrity guarantees that most data-protection regulations (GDPR, HIPAA, PCI-DSS) require for data in transit.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `ssl_action` attribute of `alicloud_mongodb_instance`, accepting a set of valid values via `get_expected_values`.
- **Expected values:** `"Open"` or `"Update"` (both indicate SSL is being turned on or an existing certificate is being rotated/updated).
- **FAIL** if `ssl_action` is missing, or set to any other value (notably `"Close"`, which disables SSL).
- **PASS** if `ssl_action` is `"Open"` or `"Update"`.

## Non-compliant example
```hcl
resource "alicloud_mongodb_instance" "example" {
  engine_version      = "4.4"
  db_instance_class   = "mdb.shard.2x.large"
  db_instance_storage = 20
  network_type        = "VPC"
  vswitch_id          = alicloud_vswitch.example.id
  ssl_action           = "Close"  # SSL disabled
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
  ssl_action           = "Open"   # <-- changed: SSL/TLS enabled
}
```

## Remediation steps
1. Set `ssl_action = "Open"` to enable SSL for the first time, or `"Update"` if rotating an existing certificate.
2. Update application/driver connection strings to require TLS (e.g., MongoDB connection URI options such as `tls=true`) and to trust the instance's CA certificate.
3. Test connectivity in a staging environment first — enforcing SSL can break clients that were relying on plaintext connections and don't have the CA certificate configured.
4. Periodically rotate the SSL certificate (`ssl_action = "Update"`) as part of routine credential/cert hygiene.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/alicloud/MongoDBInstanceSSL.py)
