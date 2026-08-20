# CKV_AWS_346: Ensure Network Firewall Policy defines an encryption configuration that uses a customer managed Key (CMK)
## Severity
**HIGH** (score: 7.5/10)

As with the firewall resource itself, the underlying firewall policy is encrypted by default with an AWS-managed key, so lacking a customer-managed key mainly reduces an organization's control over key rotation and access rather than exposing plaintext data.

## Summary
Requires AWS Network Firewall **policy** resources (`aws_networkfirewall_firewall_policy`) to specify an `encryption_configuration` with a customer-managed KMS key, rather than defaulting to the AWS-owned key.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework**: Terraform
- **Resource type**: `aws_networkfirewall_firewall_policy`

## Why it matters
A Network Firewall policy defines the stateless and stateful rule group associations, default actions, and TLS inspection configuration that governs how traffic is filtered across every firewall that uses it — effectively the security policy blueprint for a VPC's perimeter. As with the underlying firewall and rule group resources (see CKV_AWS_344/345), leaving this at the AWS-owned default key means you cannot independently audit key usage via CloudTrail, control the key's access policy, rotate it on your own schedule, or cryptographically revoke access by disabling the key. Since the policy resource can encode sensitive detail about your traffic-inspection strategy (which domains/IPs/ports are permitted or blocked), using a CMK gives you the same auditability and access-control guarantees expected of any sensitive configuration data under compliance regimes requiring customer-controlled encryption.

## How Checkov evaluates this
This is a Terraform resource value check using the `ANY_VALUE` sentinel on `encryption_configuration[0].key_id`:
- **PASS**: `encryption_configuration` is present with a non-empty `key_id`.
- **FAIL**: `encryption_configuration` is absent, or present without a `key_id` value.

## Non-compliant example
```hcl
resource "aws_networkfirewall_firewall_policy" "example" {
  name = "example-policy"

  firewall_policy {
    stateless_default_actions          = ["aws:forward_to_sfe"]
    stateless_fragment_default_actions = ["aws:forward_to_sfe"]

    stateless_rule_group_reference {
      priority     = 1
      resource_arn = aws_networkfirewall_rule_group.example.arn
    }
  }
  # no encryption_configuration -> uses AWS-owned key
}
```

## Remediated example
```hcl
resource "aws_kms_key" "firewall_policy" {
  description             = "CMK for Network Firewall policy encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_networkfirewall_firewall_policy" "example" {
  name = "example-policy"

  firewall_policy {
    stateless_default_actions          = ["aws:forward_to_sfe"]
    stateless_fragment_default_actions = ["aws:forward_to_sfe"]

    stateless_rule_group_reference {
      priority     = 1
      resource_arn = aws_networkfirewall_rule_group.example.arn
    }
  }

  encryption_configuration {
    key_id = aws_kms_key.firewall_policy.arn   # customer-managed key
    type   = "CUSTOMER_KMS"
  }
}
```

## Remediation steps
1. Create (or reuse) a customer-managed KMS key intended for Network Firewall policy encryption.
2. Add an `encryption_configuration` block to each `aws_networkfirewall_firewall_policy` resource with `type = "CUSTOMER_KMS"` and `key_id` set to the CMK ARN.
3. Grant `network-firewall.amazonaws.com` the required `kms:Decrypt` / `kms:GenerateDataKey` permissions in the key's policy.
4. Apply consistently across all firewall policies, and pair with CKV_AWS_345 so the associated firewalls and rule groups also use CMKs — mixing AWS-owned and customer-managed keys across the same firewall stack adds operational confusion.
5. This is an in-place attribute update, not a resource replacement.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/NetworkFirewallPolicyDefinesCMK.py
- AWS docs: https://docs.aws.amazon.com/network-firewall/latest/developerguide/encryption-at-rest.html
