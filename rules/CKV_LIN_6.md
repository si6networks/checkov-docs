# CKV_LIN_6: Ensure Outbound Firewall Policy is not set to ACCEPT

## Severity
**MEDIUM** (score: 5.0/10)

An ACCEPT default outbound policy weakens egress filtering and defense-in-depth against data exfiltration or C2 callbacks after a host is compromised, but does not itself expose the instance to inbound attack.

## Summary
This check ensures a Linode Cloud Firewall (`linode_firewall`) has its default `outbound_policy` set to `DROP` rather than `ACCEPT`, so unmatched outbound traffic is blocked by default instead of allowed to leave the instance.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `linode_firewall`
- **Check type:** resource-configuration attribute check

## Why it matters
An `outbound_policy` of `ACCEPT` lets a compromised instance freely reach any destination and port that isn't explicitly blocked. This matters most in a post-compromise scenario: if malware, a supply-chain-poisoned dependency, or a malicious insider gains code execution on the host, an unrestricted egress policy lets it exfiltrate data to arbitrary external endpoints, phone home to command-and-control infrastructure, or pivot to attack other internal/external systems — all without tripping any firewall rule. A default-deny (`DROP`) outbound policy forces all egress to be explicitly enumerated, so unexpected outbound connections (a strong compromise indicator) get blocked rather than silently succeeding, and are far easier to detect via connection-attempt logging.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `outbound_policy` attribute of the `linode_firewall` resource. The check expects the value to equal `"DROP"`. If `outbound_policy` is `"ACCEPT"` (or anything other than `DROP`), the check FAILS; if it is `"DROP"`, the check PASSES.

## Non-compliant example
```hcl
resource "linode_firewall" "app_fw" {
  label           = "app-firewall"
  inbound_policy  = "DROP"
  outbound_policy = "ACCEPT"

  outbound {
    label    = "allow-dns"
    action   = "ACCEPT"
    protocol = "UDP"
    ports    = "53"
    ipv4     = ["0.0.0.0/0"]
  }
}
```

## Remediated example
```hcl
resource "linode_firewall" "app_fw" {
  label           = "app-firewall"
  inbound_policy  = "DROP"
  outbound_policy = "DROP"

  outbound {
    label    = "allow-dns"
    action   = "ACCEPT"
    protocol = "UDP"
    ports    = "53"
    ipv4     = ["0.0.0.0/0"]
  }

  outbound {
    label    = "allow-https-egress"
    action   = "ACCEPT"
    protocol = "TCP"
    ports    = "443"
    ipv4     = ["0.0.0.0/0"]
  }
}
```

## Remediation steps
1. Set `outbound_policy = "DROP"` on every `linode_firewall` resource.
2. Explicitly allow only the egress your workload genuinely needs (e.g. DNS on 53, HTTPS to package registries/APIs on 443, database ports to specific internal ranges) via `outbound` rule blocks.
3. Audit application/service dependencies first (package managers, telemetry endpoints, license servers, etc.) so the default-deny rollout doesn't break legitimate functionality.
4. Monitor firewall drop logs after rollout to catch missed legitimate flows and to spot suspicious blocked egress attempts.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/linode/firewall_outbound_policy.py)
- [Linode Terraform provider: linode_firewall](https://registry.terraform.io/providers/linode/linode/latest/docs/resources/firewall)
