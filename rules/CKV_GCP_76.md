# CKV_GCP_76: Ensure that Private Google Access is enabled for IPv6
## Severity
**MEDIUM** (score: 4.5/10)

Disabled IPv6 Private Google Access is the dual-stack counterpart of CKV_GCP_74 and carries the same indirect attack-surface risk rather than a direct exposure.

## Summary
This check ensures dual-stack (IPv4/IPv6) subnetworks enable Private Google Access over IPv6, so instances using IPv6-only or dual-stack addressing can still reach Google APIs privately.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_compute_subnetwork`

## Why it matters
This is the IPv6 counterpart to standard (IPv4) Private Google Access (CKV_GCP_74). As organizations adopt dual-stack networking, instances communicating over IPv6 need an equivalent mechanism to reach Google APIs and services without a public IPv6 address or open internet route. If `private_ipv6_google_access` is left disabled on a dual-stack subnet, IPv6-addressed workloads either cannot reach Google services at all, or administrators are pushed to expose broader IPv6 internet routes/external addressing to compensate — again expanding the internet-facing attack surface. Keeping this traffic on Google's private backbone avoids that trade-off entirely.

## How Checkov evaluates this
Checkov inspects `google_compute_subnetwork` and first applies two "not applicable" carve-outs, both returning `UNKNOWN` (not evaluated) rather than PASS/FAIL:
- If `purpose` is `INTERNAL_HTTPS_LOAD_BALANCER`, `REGIONAL_MANAGED_PROXY`, or `GLOBAL_MANAGED_PROXY` (the setting doesn't apply to these).
- If `stack_type` is not set to `"IPV4_IPV6"` (i.e., the subnet isn't dual-stack, so IPv6 Google Access is meaningless).

For subnets that are dual-stack and not one of those special purposes, it checks `private_ipv6_google_access`, which must be one of `"ENABLE_OUTBOUND_VM_ACCESS_TO_GOOGLE"` or `"ENABLE_BIDIRECTIONAL_ACCESS_TO_GOOGLE"` to PASS. Any other value (or the attribute unset) FAILS.

## Non-compliant example
```hcl
resource "google_compute_subnetwork" "dual_stack_subnet" {
  name          = "dual-stack-subnet"
  ip_cidr_range = "10.30.0.0/24"
  region        = "us-central1"
  network       = google_compute_network.vpc.id
  stack_type    = "IPV4_IPV6"
  ipv6_access_type = "INTERNAL"
  # private_ipv6_google_access omitted
}
```

## Remediated example
```hcl
resource "google_compute_subnetwork" "dual_stack_subnet" {
  name                      = "dual-stack-subnet"
  ip_cidr_range             = "10.30.0.0/24"
  region                    = "us-central1"
  network                   = google_compute_network.vpc.id
  stack_type                = "IPV4_IPV6"
  ipv6_access_type          = "INTERNAL"
  private_ipv6_google_access = "ENABLE_OUTBOUND_VM_ACCESS_TO_GOOGLE"
}
```

## Remediation steps
1. For any dual-stack (`stack_type = "IPV4_IPV6"`) subnetwork, add `private_ipv6_google_access` set to `"ENABLE_OUTBOUND_VM_ACCESS_TO_GOOGLE"` (outbound only) or `"ENABLE_BIDIRECTIONAL_ACCESS_TO_GOOGLE"` (if inbound access from Google is also required).
2. Confirm this check is not applicable (and can be safely ignored) for single-stack IPv4 subnets or subnets with `purpose` set to a managed-proxy/ILB value.
3. Verify the containing VPC network has IPv6 enabled (`enable_ula_internal_ipv6` or external IPv6 range, depending on design) before configuring subnet-level settings.
4. This is an in-place update to the subnetwork; no resource replacement is required.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleSubnetworkIPV6PrivateGoogleEnabled.py)
- [Google Cloud: Private Google Access](https://cloud.google.com/vpc/docs/private-google-access)
