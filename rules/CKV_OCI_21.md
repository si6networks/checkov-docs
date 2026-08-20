# CKV_OCI_21: Ensure security group has stateless ingress security rules

## Severity
**MEDIUM** (score: 5.0/10)

Non-stateless ingress rules on network security groups can allow unintended stateful return-path traffic, marginally broadening effective exposure without being a direct exploit vector on their own.

## Summary
This check ensures that ingress rules within an OCI Network Security Group (`oci_core_network_security_group_security_rule`) are explicitly marked `stateless = true`, rather than relying on the default stateful behavior.

## Applicability
- **Framework:** Terraform
- **Resource type:** `oci_core_network_security_group_security_rule`

## Why it matters
Like security lists, Network Security Group (NSG) rules default to stateful behavior — once an inbound connection is allowed, its response traffic is automatically permitted, bypassing whatever egress rules you have configured. This creates an implicit trust relationship between ingress and egress control planes: your careful egress restrictions (intended to limit data exfiltration or command-and-control callback channels) can be silently circumvented for any traffic that is the "reply" to an inbound connection. Requiring stateless ingress rules forces explicit, symmetric authorization of both directions of traffic, closing this gap and giving security teams full visibility and control over exactly what traffic flows are permitted in each direction — important for NSGs protecting sensitive workloads (databases, internal APIs) where exfiltration-path control matters as much as inbound access control.

## How Checkov evaluates this
This is a custom `BaseResourceCheck` on `oci_core_network_security_group_security_rule`. It reads the `direction` and `stateless` attributes. The check only evaluates rules where `direction == "INGRESS"` (egress rules return UNKNOWN/not applicable). For an ingress rule, it FAILS if `stateless` is `None` (unset, defaulting to stateful) or explicitly `False`. It PASSES only if `stateless` is explicitly `True`.

## Non-compliant example
```hcl
resource "oci_core_network_security_group_security_rule" "app_ingress" {
  network_security_group_id = oci_core_network_security_group.app_nsg.id
  direction                 = "INGRESS"
  protocol                  = "6"
  source                    = "10.0.0.0/16"
  source_type               = "CIDR_BLOCK"
  # stateless omitted - defaults to stateful

  tcp_options {
    destination_port_range {
      min = 443
      max = 443
    }
  }
}
```

## Remediated example
```hcl
resource "oci_core_network_security_group_security_rule" "app_ingress" {
  network_security_group_id = oci_core_network_security_group.app_nsg.id
  direction                 = "INGRESS"
  protocol                  = "6"
  source                    = "10.0.0.0/16"
  source_type               = "CIDR_BLOCK"
  stateless                 = true

  tcp_options {
    destination_port_range {
      min = 443
      max = 443
    }
  }
}
```

## Remediation steps
1. Add `stateless = true` to every `oci_core_network_security_group_security_rule` resource with `direction = "INGRESS"`.
2. Add a corresponding, explicit egress rule for the response traffic of each stateless ingress rule, since stateless rules require both directions to be separately authorized.
3. Test connectivity thoroughly after conversion — this is a behavioral change and a missing egress counterpart will silently break legitimate connections.
4. Evaluate on a per-NSG basis: for lower-sensitivity workloads the operational simplicity of stateful rules may be an acceptable trade-off; prioritize stateless enforcement for NSGs guarding sensitive data stores or egress-restricted workloads.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/oci/SecurityGroupsIngressStatelessSecurityRules.py)
