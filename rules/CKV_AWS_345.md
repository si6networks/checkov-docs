# CKV_AWS_345: Ensure that Network firewall encryption is via a CMK
## Severity
**HIGH** (score: 7.5/10)

Network Firewall resources are already encrypted at rest by AWS-managed keys by default, so omitting a customer-managed key mainly weakens key-management control (rotation, access auditing, revocation) rather than leaving the data unencrypted.

## Summary
Requires AWS Network Firewall firewalls and rule groups to be encrypted with a customer-managed KMS key (CMK) rather than relying on the AWS-owned/managed default key.

## Applicability
- **Framework**: Terraform
- **Resource types**: `aws_networkfirewall_firewall`, `aws_networkfirewall_rule_group`

## Why it matters
AWS Network Firewall resources (firewall configuration and rule groups, which can contain sensitive information such as internal domain allow/deny lists, IP ranges, or detection signatures revealing your security posture) are encrypted at rest by default using an AWS-owned key that you cannot view, rotate, restrict, or audit access to independently. Using a customer-managed KMS key instead gives you control over the key policy (who can decrypt), independent key rotation schedule, CloudTrail visibility into every `Decrypt`/`GenerateDataKey` call, and the ability to instantly revoke access (disable/schedule deletion of the key) to cryptographically deny access to the resource's configuration data — a capability required by many compliance frameworks (PCI-DSS, HIPAA, FedRAMP) that mandate customer control over encryption keys for sensitive infrastructure configuration.

## How Checkov evaluates this
This is a Terraform resource value check using the special `ANY_VALUE` sentinel on the attribute path `encryption_configuration[0].key_id`:
- **PASS**: `encryption_configuration` block is present and its `key_id` is set to any non-empty value (i.e., a CMK ARN/ID is supplied).
- **FAIL**: the `encryption_configuration` block is missing, or present without a `key_id` (which means AWS falls back to its own managed key rather than your CMK).

## Non-compliant example
```hcl
resource "aws_networkfirewall_firewall" "example" {
  name                = "example-firewall"
  firewall_policy_arn = aws_networkfirewall_firewall_policy.example.arn
  vpc_id              = aws_vpc.example.id

  subnet_mapping {
    subnet_id = aws_subnet.firewall.id
  }
  # no encryption_configuration -> uses AWS-owned key, not a CMK
}
```

## Remediated example
```hcl
resource "aws_kms_key" "firewall" {
  description             = "CMK for Network Firewall encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_networkfirewall_firewall" "example" {
  name                = "example-firewall"
  firewall_policy_arn = aws_networkfirewall_firewall_policy.example.arn
  vpc_id              = aws_vpc.example.id

  subnet_mapping {
    subnet_id = aws_subnet.firewall.id
  }

  encryption_configuration {
    key_id = aws_kms_key.firewall.arn   # customer-managed key
    type   = "CUSTOMER_KMS"
  }
}
```

## Remediation steps
1. Create (or identify an existing) customer-managed KMS key intended for Network Firewall use, with an appropriate key policy limiting who can use/administer it.
2. Add an `encryption_configuration` block to each `aws_networkfirewall_firewall` and `aws_networkfirewall_rule_group` resource, setting `type = "CUSTOMER_KMS"` and `key_id` to the CMK's ARN.
3. Grant the Network Firewall service principal (`network-firewall.amazonaws.com`) the necessary `kms:Decrypt`/`kms:GenerateDataKey` permissions in the key policy.
4. Enable automatic key rotation on the CMK (`enable_key_rotation = true`) for defense in depth.
5. Note: switching an existing firewall/rule group from AWS-owned key to a CMK is supported as an in-place update via the API/Terraform, but verify in a non-production environment first since it changes the encryption context.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/NetworkFirewallUsesCMK.py
- AWS docs: https://docs.aws.amazon.com/network-firewall/latest/developerguide/encryption-at-rest.html
