# CKV_GCP_74: Ensure that private_ip_google_access is enabled for Subnet
## Severity
**MEDIUM** (score: 4.5/10)

Disabled Private Google Access mainly pressures operators toward assigning unnecessary external IPs or broader egress rules, an indirect attack-surface increase rather than a direct exposure.

## Summary
This check ensures VM instances in a GCP subnetwork that lack external IP addresses can still reach Google APIs and services privately, rather than being unable to reach them (or being tempted to route through a public IP/NAT unnecessarily).

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_compute_subnetwork`

## Why it matters
Private Google Access lets instances with only internal IP addresses reach Google APIs and services (Cloud Storage, BigQuery, Container Registry, etc.) without needing a public IP or routing through the public internet. When this is disabled, operators are pushed toward compensating patterns that weaken the security posture: assigning external IPs to instances that shouldn't need them (increasing the internet-facing attack surface), or building broader NAT/egress rules than necessary. It also has an availability angle — private-only workloads that need to pull container images, write logs, or call other Google APIs will simply fail to reach them if this is left off. Enabling it keeps such traffic on Google's private backbone rather than transiting the public internet, improving both security and reliability of intra-Google-Cloud communication.

## How Checkov evaluates this
Checkov reads `private_ip_google_access` on the `google_compute_subnetwork` resource, expecting it to be truthy to PASS. Before that, it applies an exception: if the subnet's `purpose` is one of `INTERNAL_HTTPS_LOAD_BALANCER`, `REGIONAL_MANAGED_PROXY`, or `GLOBAL_MANAGED_PROXY` — special-purpose subnets that don't support this setting — the result is `UNKNOWN` rather than PASS/FAIL. Otherwise, `private_ip_google_access != true` (unset or `false`) FAILS.

## Non-compliant example
```hcl
resource "google_compute_subnetwork" "app_subnet" {
  name          = "app-subnet"
  ip_cidr_range = "10.10.0.0/24"
  region        = "us-central1"
  network       = google_compute_network.vpc.id
  # private_ip_google_access omitted -> defaults to false
}
```

## Remediated example
```hcl
resource "google_compute_subnetwork" "app_subnet" {
  name                     = "app-subnet"
  ip_cidr_range            = "10.10.0.0/24"
  region                   = "us-central1"
  network                  = google_compute_network.vpc.id
  private_ip_google_access = true
}
```

## Remediation steps
1. Add `private_ip_google_access = true` to each `google_compute_subnetwork` resource that hosts internal-only workloads needing to reach Google APIs.
2. Skip/ignore this setting for subnets whose `purpose` is `INTERNAL_HTTPS_LOAD_BALANCER`, `REGIONAL_MANAGED_PROXY`, or `GLOBAL_MANAGED_PROXY` — the API does not support it there, and Checkov correctly reports these as `UNKNOWN` rather than failing.
3. This is a live, in-place update on an existing subnetwork — no resource replacement or downtime is required.
4. If instances still need general internet egress (not just Google API access), pair this with a Cloud NAT gateway rather than assigning external IPs.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleSubnetworkPrivateGoogleEnabled.py)
- [Google Cloud: Private Google Access](https://cloud.google.com/vpc/docs/private-google-access)
