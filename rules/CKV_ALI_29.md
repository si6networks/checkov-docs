# CKV_ALI_29: Alibaba ALB ACL does not restrict Access
## Severity
**HIGH** (score: 7.0/10)

An ALB ACL entry permitting 0.0.0.0/0 removes the access-control layer intended to restrict which clients can reach backend services through the load balancer, broadening network exposure of potentially sensitive application endpoints.

## Summary
This check fails any Alibaba Cloud Application Load Balancer (ALB) ACL entry attachment whose entry allows the unrestricted CIDR `0.0.0.0/0`.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `alicloud_alb_acl_entry_attachment`

## Why it matters
An ALB Access Control List (ACL) is meant to restrict which source IP addresses can reach the load balancer's listeners — commonly used to allowlist a corporate network, partner IP ranges, or a CDN's edge IPs while blocking everything else. If an ACL entry itself contains `0.0.0.0/0`, it effectively negates the purpose of using an ACL at all: any client on the internet can reach the backend service through the load balancer, exposing whatever application logic sits behind it to unrestricted internet traffic (increasing exposure to DDoS, scanning, exploitation attempts, and unauthorized access to endpoints that were assumed to be network-restricted).

## How Checkov evaluates this
This is a `BaseResourceNegativeValueCheck` (a "forbidden value" check) on `alicloud_alb_acl_entry_attachment`:
- Inspects the `entry` attribute.
- FAILS if `entry` equals the forbidden value `"0.0.0.0/0"`.
- PASSES for any other CIDR value.

## Non-compliant example
```hcl
resource "alicloud_alb_acl" "example" {
  acl_name    = "example-acl"
  acl_entries {
    entry   = "0.0.0.0/0"
    description = "allow all"
  }
}

resource "alicloud_alb_acl_entry_attachment" "example" {
  acl_id      = alicloud_alb_acl.example.id
  entry       = "0.0.0.0/0"   # <-- fails: unrestricted access
  description = "example-entry"
}
```

## Remediated example
```hcl
resource "alicloud_alb_acl" "example" {
  acl_name = "example-acl"
}

resource "alicloud_alb_acl_entry_attachment" "example" {
  acl_id      = alicloud_alb_acl.example.id
  entry       = "203.0.113.0/24"   # <-- fix: scoped to a specific trusted range
  description = "corporate-network"
}
```

## Remediation steps
1. Identify every `alicloud_alb_acl_entry_attachment` resource with `entry = "0.0.0.0/0"`.
2. Replace the CIDR with the specific, minimal set of source ranges that legitimately need access (office/VPN CIDR, partner IP block, known CDN edge ranges).
3. If the ALB is genuinely meant to be public-facing (e.g. a public website), consider whether an ACL is the right control at all — a "black hole" allow-all ACL entry provides no actual restriction and should either be removed (relying on the ALB's default open behavior, if intentional) or replaced with a real allowlist plus other protections such as a WAF.
4. Apply the change; this is generally an in-place update to the ACL entry with no listener downtime.
5. Re-scan with checkov to confirm no ACL entries use `0.0.0.0/0`.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/alicloud/ALBACLIsUnrestricted.py)
- [Alibaba Cloud ALB ACL entry attachment resource docs](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/alb_acl_entry_attachment)
