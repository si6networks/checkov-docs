# CKV_OCI_17: Ensure VCN inbound security lists are stateless

## Severity
**MEDIUM** (score: 4.5/10)

Stateful vs. stateless ingress rules affect how return traffic and connection tracking are handled; using stateful rules where stateless was intended can subtly widen effective network exposure but is not itself a direct compromise path.

## Summary
This check ensures that ingress rules within an OCI VCN security list (`oci_core_security_list`) are explicitly marked `stateless = true`, rather than left as stateful (the default).

## Applicability
- **Framework:** Terraform
- **Resource type:** `oci_core_security_list`

## Why it matters
By default, OCI security list rules are stateful, meaning that once an inbound connection is permitted, the corresponding outbound response traffic is automatically allowed regardless of egress rules — the return traffic bypasses your explicit egress policy. This convenience can undermine defense-in-depth: if you rely on egress rules to constrain what an instance can send out (e.g., blocking exfiltration channels), stateful ingress rules silently create implicit reply-traffic exceptions to that policy for any connection an attacker or compromised process manages to initiate inbound. Requiring stateless rules forces both ingress and egress traffic to be explicitly and separately authorized, giving you full, unambiguous control over the traffic matrix and preventing an accidental "open door" for return traffic tied to an inbound rule you didn't fully consider from an egress-control standpoint.

## How Checkov evaluates this
This is a custom `BaseResourceCheck` that iterates through the resource's `ingress_security_rules` list (handling both the older list-of-maps Terraform provider syntax and the newer block syntax). For each rule, it inspects the `stateless` field. The check FAILS if any rule sets `stateless` to a value that is not `True`/`[True]` (i.e., stateless is `false`, or absent and therefore defaulting to stateful behavior). It PASSES if every rule explicitly has `stateless = true`. If no `ingress_security_rules` key is present at all, the result is UNKNOWN (not evaluated).

## Non-compliant example
```hcl
resource "oci_core_security_list" "app_sl" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.main.id
  display_name   = "app-security-list"

  ingress_security_rules {
    protocol = "6"
    source   = "10.0.0.0/16"
    # stateless omitted - defaults to stateful (false)

    tcp_options {
      min = 443
      max = 443
    }
  }
}
```

## Remediated example
```hcl
resource "oci_core_security_list" "app_sl" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.main.id
  display_name   = "app-security-list"

  ingress_security_rules {
    protocol  = "6"
    source    = "10.0.0.0/16"
    stateless = true

    tcp_options {
      min = 443
      max = 443
    }
  }
}
```

## Remediation steps
1. Add `stateless = true` to every `ingress_security_rules` block in the security list.
2. Add matching, explicit `egress_security_rules` for the return traffic of each stateless ingress rule you define, since stateless rules require both directions to be explicitly authorized.
3. Test connectivity carefully after this change — converting from stateful to stateless is a behavioral change that can silently break existing connections if the corresponding egress rule is missing.
4. Weigh this against your architecture: for many simple internal use cases the default stateful behavior is intentional and low-risk; apply stateless rules primarily where you need airtight, explicit control over both traffic directions.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/oci/SecurityListIngressStateless.py)
