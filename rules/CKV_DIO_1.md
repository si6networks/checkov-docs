# CKV_DIO_1: Ensure the Spaces bucket has versioning enabled

## Severity
**MEDIUM** (score: 4.5/10)

Missing versioning on a Spaces bucket weakens recovery from accidental deletion, overwrite, or ransomware-style tampering, an availability/data-integrity concern rather than a direct confidentiality exposure.

## Summary
This check requires that a DigitalOcean Spaces bucket (`digitalocean_spaces_bucket`) has object versioning enabled, so that overwritten or deleted objects can be recovered.

## Applicability
**Checkov framework(s):** `terraform`

Terraform resource type `digitalocean_spaces_bucket` (DigitalOcean provider). Specifically inspects the `versioning` block's `enabled` attribute (`versioning[0].enabled`).

## Why it matters
Without versioning, any accidental overwrite, unintended deletion, or malicious tampering (e.g., via a leaked API key or ransomware-style attack that encrypts/overwrites objects) permanently destroys the prior object content — there is no way to recover the previous state. Versioning preserves every prior version of an object, which is a foundational control for data durability and for recovering from both operational mistakes and security incidents (e.g., an attacker who gains write access and deletes or corrupts data). This is analogous to S3 bucket versioning best practices and falls under backup-and-recovery hygiene.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the resource's `versioning/[0]/enabled` attribute. It PASSES only when a `versioning` block is present and its `enabled` attribute is set to `true`. If the `versioning` block is absent, or present with `enabled = false` (or unset, which defaults to `false` in the provider), the check FAILS.

## Non-compliant example
```hcl
resource "digitalocean_spaces_bucket" "assets" {
  name   = "example-assets"
  region = "nyc3"
}
```

## Remediated example
```hcl
resource "digitalocean_spaces_bucket" "assets" {
  name   = "example-assets"
  region = "nyc3"

  versioning {
    enabled = true
  }
}
```

## Remediation steps
1. Add a `versioning` block to the `digitalocean_spaces_bucket` resource.
2. Set `enabled = true` inside that block.
3. Apply the change via Terraform; note that enabling versioning does not require bucket recreation, but be aware storage costs will increase as prior object versions accumulate.
4. Pair versioning with a lifecycle rule (`lifecycle_rule`) to expire old noncurrent versions after a retention period, to control storage growth.
5. Re-run `terraform plan`/`checkov` to confirm the resource now passes.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/digitalocean/SpacesBucketVersioning.py
- DigitalOcean Terraform provider docs: https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/spaces_bucket
