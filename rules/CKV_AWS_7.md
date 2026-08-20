# CKV_AWS_7: Ensure rotation for customer created CMKs is enabled
## Severity
**LOW** (score: 2.0/10)

Disabled automatic key rotation for a customer-managed KMS key increases the long-term risk of key compromise going undetected, weakening cryptographic hygiene without itself directly exposing data absent a separate breach.

## Summary
This check verifies that a customer-managed KMS key (CMK) has automatic annual key rotation enabled, but only applies this requirement to symmetric (or HMAC) keys, since asymmetric keys do not support automatic rotation.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **CloudFormation**: `AWS::KMS::Key`, properties `Properties/EnableKeyRotation` and `Properties/KeySpec`.
- **Terraform**: `aws_kms_key` resource, attributes `enable_key_rotation` and `customer_master_key_spec`.

## Why it matters
Key rotation is a defense-in-depth control that limits the amount of ciphertext ever protected by a single cryptographic key version, reducing the impact if a key is ever compromised, and supporting cryptographic hygiene best practices required by many compliance frameworks (PCI-DSS, NIST 800-57 key-management guidance). With AWS KMS automatic rotation enabled, AWS generates new cryptographic material for the CMK every year while retaining the old material to decrypt data previously encrypted under it — transparently to applications, since the key ID/ARN doesn't change. Without rotation, a CMK's underlying key material remains static indefinitely; if that material were ever exposed (e.g. via a catastrophic AWS-side incident, insider threat, or cryptanalytic advance) all data ever encrypted with it would be at risk with no time-bounded mitigation already in place. The check correctly restricts its scope to symmetric/HMAC keys because AWS KMS asymmetric keys (RSA/ECC used for sign/verify or encrypt/decrypt with external tooling) fundamentally do not support automatic rotation — flagging them would be a false positive.

## How Checkov evaluates this
Both implementations wrap a `BaseResourceValueCheck` whose base behavior inspects `EnableKeyRotation`/`enable_key_rotation` for the value `true`, but first apply a **key-spec pre-filter**:
- Read the key's spec: `Properties/KeySpec` (CloudFormation) or `customer_master_key_spec` (Terraform).
- If the spec is set and does **not** contain `"SYMMETRIC_DEFAULT"` and does **not** contain `"HMAC"` (i.e., it's an asymmetric key like `RSA_2048`, `ECC_NIST_P256`, etc.) → return **UNKNOWN** (not applicable; rotation isn't supported so the check is skipped rather than failed).
- Otherwise (spec is unset — which defaults to symmetric — or explicitly symmetric/HMAC) → fall through to the base check: PASS if `EnableKeyRotation`/`enable_key_rotation` is `true`; FAIL if it's `false` or unset.

## Non-compliant example
```hcl
resource "aws_kms_key" "app_data" {
  description = "CMK for encrypting app data"
  # customer_master_key_spec unset -> defaults to SYMMETRIC_DEFAULT
  # enable_key_rotation not set -> defaults to false, non-compliant
}
```

## Remediated example
```hcl
resource "aws_kms_key" "app_data" {
  description         = "CMK for encrypting app data"
  enable_key_rotation = true    # fixed
}
```

## Remediation steps
1. Set `enable_key_rotation = true` (Terraform) or `EnableKeyRotation: true` (CloudFormation) on the `aws_kms_key` / `AWS::KMS::Key` resource.
2. Verify the key's `customer_master_key_spec`/`KeySpec` — if it is genuinely an asymmetric key (RSA/ECC) intentionally used for sign/verify or external encrypt/decrypt, rotation isn't available and this check will correctly report `UNKNOWN`/not applicable rather than fail; no action is needed in that case.
3. This is a non-disruptive, in-place setting — AWS handles rotation transparently and existing ciphertext remains decryptable.
4. Note AWS's default annual rotation cadence cannot be customized per-key via this attribute (it's a simple on/off toggle); AWS handles the exact rotation schedule internally.
5. For imported (external) key material, automatic rotation is not supported at all regardless of this setting — you must manually re-import new key material and manage rotation yourself.

## References
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/KMSRotation.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/KMSRotation.py)
- [AWS: Rotating AWS KMS keys](https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html)
