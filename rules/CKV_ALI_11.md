# CKV_ALI_11: Ensure OSS bucket has transfer Acceleration enabled

## Severity
**LOW** (score: 2.0/10)

Transfer Acceleration is primarily a performance/reliability feature for geographically distributed clients; its absence has minimal direct security impact and mainly affects operational efficiency.

## Summary
This check ensures Alibaba Cloud OSS buckets have Transfer Acceleration enabled (`transfer_acceleration[0].enabled = true`), which routes object upload/download traffic over Alibaba Cloud's global accelerated network edge rather than the public internet path directly to the bucket's region.

## Applicability
**Checkov framework(s):** `terraform`

Terraform. Applies to the `alicloud_oss_bucket` resource, specifically its `transfer_acceleration[0].enabled` attribute.

## Why it matters
Checkov categorizes this as a `GENERAL_SECURITY` check, but the underlying control is primarily an availability/reliability and data-integrity-in-transit feature rather than a confidentiality control: Transfer Acceleration routes traffic through Alibaba Cloud's globally distributed edge nodes over an optimized backbone network instead of the unpredictable public internet path. For geographically distributed clients (e.g. users or services far from the bucket's region), this reduces the exposure window of data in transit across the public internet, improves upload/download reliability, and reduces the chance of degraded-connection failures that could cause retries, partial uploads, or client-side workarounds (such as disabling TLS verification) that weaken security. It's most relevant for buckets serving or receiving traffic from geographically dispersed users, CI/CD pipelines, or multi-region architectures.

## How Checkov evaluates this
This is a Python check (`OSSBucketTransferAcceleration.py`) extending `BaseResourceValueCheck`. It inspects the key `transfer_acceleration/[0]/enabled` on the `alicloud_oss_bucket` resource. Since no `get_expected_value()` override beyond the base class default is provided, the check expects this to be truthy (`true`); if the `transfer_acceleration` block is absent or `enabled` is `false`, the check fails.

## Non-compliant example
```hcl
resource "alicloud_oss_bucket" "assets" {
  bucket = "company-global-assets"
  acl    = "private"
  # no transfer_acceleration block - disabled by default
}
```

## Remediated example
```hcl
resource "alicloud_oss_bucket" "assets" {
  bucket = "company-global-assets"
  acl    = "private"

  transfer_acceleration {
    enabled = true
  }
}
```

## Remediation steps
1. Add a `transfer_acceleration` block with `enabled = true` to the `alicloud_oss_bucket` resource.
2. Confirm the bucket name is DNS-compliant (no periods) — Alibaba Cloud requires this for transfer acceleration to function correctly.
3. Update client SDKs/CLI configuration to use the acceleration endpoint (`<bucket>.oss-accelerate.aliyuncs.com`) to actually benefit from the feature; simply enabling it on the bucket does not redirect existing clients automatically.
4. Evaluate cost impact — transfer acceleration typically carries an additional per-GB charge compared to standard transfer.
5. For buckets with no geographically distributed access patterns (e.g. purely intra-region service-to-service traffic), weigh whether this control provides meaningful benefit versus its cost before enabling broadly.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/alicloud/OSSBucketTransferAcceleration.py
