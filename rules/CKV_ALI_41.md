# CKV_ALI_41: Ensure MongoDB is deployed inside a VPC
## Severity
**LOW** (score: 2.0/10)

A MongoDB instance deployed outside a VPC is reachable over the classic/public network layer rather than isolated private networking, materially increasing its exposure to network-based attacks.

## Summary
This check ensures that an Alibaba Cloud ApsaraDB for MongoDB instance is deployed within a Virtual Private Cloud (`network_type = "VPC"`) rather than the legacy Classic network.

## Applicability
- **Framework:** Terraform
- **Resource type:** `alicloud_mongodb_instance`

## Why it matters
Alibaba Cloud's legacy "Classic" network provides weaker network isolation than a VPC: Classic-network resources share a broader, less segmented network space, offer less granular security-group/ACL control, and lack the fine-grained private subnetting, route table control, and network ACL capabilities of a VPC. Running a database — which typically holds an organization's most sensitive data — outside a VPC increases its exposure surface, makes it harder to enforce least-privilege network segmentation between application tiers, and complicates consistent enforcement of private connectivity (e.g., VPC peering, PrivateLink-style endpoints) that a VPC-native deployment enables. Deploying inside a VPC is a foundational step toward eliminating public exposure and constraining lateral movement in the event some other component is compromised.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `network_type` attribute of `alicloud_mongodb_instance`.
- **FAIL** if `network_type` is missing or set to any value other than `"VPC"` (e.g., `"Classic"`).
- **PASS** if `network_type = "VPC"`.

## Non-compliant example
```hcl
resource "alicloud_mongodb_instance" "example" {
  engine_version      = "4.4"
  db_instance_class   = "mdb.shard.2x.large"
  db_instance_storage = 20
  network_type        = "Classic"
}
```

## Remediated example
```hcl
resource "alicloud_mongodb_instance" "example" {
  engine_version      = "4.4"
  db_instance_class   = "mdb.shard.2x.large"
  db_instance_storage = 20
  network_type        = "VPC"          # <-- changed: deploy inside a VPC
  vswitch_id          = alicloud_vswitch.example.id
}
```

## Remediation steps
1. Set `network_type = "VPC"` on the `alicloud_mongodb_instance` resource.
2. Provide a valid `vswitch_id` referencing a VSwitch within your target VPC — required once `network_type` is `"VPC"`.
3. Be aware: changing `network_type` on an existing Classic-network instance is generally not an in-place update — it typically requires migrating/recreating the instance into the VPC, so plan for a maintenance window and data migration/backup strategy.
4. After migration, tighten the associated `security_ips`/security group rules to only permit application-tier CIDR ranges (see also CKV_ALI_43 for public-exposure checks on MongoDB).

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/alicloud/MongoDBInsideVPC.py)
