# CKV2_GCP_12: Ensure GCP compute firewall ingress does not allow unrestricted access to all ports
## Severity
**CRITICAL** (score: 9.5/10)

A firewall rule that allows ingress on all ports/protocols from unrestricted source ranges (e.g. 0.0.0.0/0) effectively removes network segmentation and exposes every service on the matched instances directly to the internet.

## Summary
This check flags `google_compute_firewall` ingress rules that allow all protocols/ports from any source (`0.0.0.0/0` or `::/0`), unless the rule is disabled, is an egress rule, or explicitly denies (rather than allows) all traffic.

## Applicability
**Checkov framework(s):** `terraform`

Applies to Terraform, specifically the `google_compute_firewall` resource.

## Why it matters
A firewall rule that allows `protocol = "all"` (or an equivalent open-all-ports allow) from `0.0.0.0/0` exposes every port on every instance the rule applies to directly to the entire internet. This is one of the most dangerous possible network misconfigurations: it removes any port-level segmentation, meaning services never intended to be internet-facing (databases, internal admin panels, debug endpoints, SSH/RDP, metadata proxies) become reachable by any attacker who simply scans the instance's public IP. Combined with any single vulnerable service running on the instance, this turns a narrow application-level bug into full host compromise, lateral movement into the VPC, and potential access to internal-only resources that assumed network-level isolation as a security boundary.

## How Checkov evaluates this
This is an `or` of five `attribute` conditions on `google_compute_firewall` — the check PASSes (is not flagged) if **any** of these hold:
1. `disabled == true` — the rule is disabled, so it has no effect.
2. `direction == "EGRESS"` — the check only cares about ingress exposure.
3. `allow.protocol != "all"` — the rule doesn't allow *all* protocols/ports (i.e. it's scoped to specific ports/protocols).
4. `deny.protocol == "all"` — the rule is a deny-all rule, not an allow-all rule.
5. `source_ranges` does **not** intersect `["::/0", "::0", "0.0.0.0", "0.0.0.0/0"]` — the rule isn't open to the whole internet.

The check FAILs only when none of these apply — i.e. an enabled, ingress, allow rule with `protocol = "all"` and a source range that includes the entire internet (`0.0.0.0/0` or `::/0`).

## Non-compliant example
```hcl
resource "google_compute_firewall" "allow_all_ingress" {
  name    = "allow-all-ingress"
  network = google_compute_network.vpc.name

  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "all"
  }
}
```

## Remediated example
```hcl
resource "google_compute_firewall" "allow_https_from_lb" {
  name    = "allow-https-from-lb"
  network = google_compute_network.vpc.name

  direction     = "INGRESS"
  source_ranges = ["35.191.0.0/16", "130.211.0.0/22"]  # GCP health-check / LB ranges

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}
```

## Remediation steps
1. Scope `allow.protocol` to the specific protocol(s) actually needed (`tcp`, `udp`, `icmp`) instead of `"all"`.
2. Scope `allow.ports` to only the required port(s) (e.g. `["443"]`), never leave it open-ended.
3. Restrict `source_ranges` to known, necessary CIDR blocks (load balancer health-check ranges, corporate VPN/bastion ranges, peered VPCs) instead of `0.0.0.0/0`/`::/0`.
4. Prefer `source_tags` or `source_service_accounts` combined with narrow `target_tags`/`target_service_accounts` for fine-grained, identity-based segmentation over broad CIDR-based rules.
5. If a rule truly must be open temporarily, set `disabled = true` when not in use and add monitoring/alerting on the rule's existence.
6. Re-run Checkov / `terraform plan` to confirm.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/gcp/GCPComputeFirewallOverlyPermissiveToAllTraffic.json
- GCP docs: https://cloud.google.com/firewall/docs/firewalls
