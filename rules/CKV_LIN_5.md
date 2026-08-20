# CKV_LIN_5: Ensure Inbound Firewall Policy is not set to ACCEPT

## Severity
**HIGH** (score: 7.5/10)

A firewall whose default inbound policy is ACCEPT rather than DROP silently allows any traffic not covered by an explicit rule, broadly exposing every service on the instance to the network by default.

## Summary
This check ensures a Linode Cloud Firewall (`linode_firewall`) has its default `inbound_policy` set to `DROP` rather than `ACCEPT`, so that any traffic not explicitly matched by a firewall rule is blocked instead of allowed through.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `linode_firewall`
- **Check type:** resource-configuration attribute check

## Why it matters
A firewall's default policy determines what happens to packets that don't match any explicit rule. Setting `inbound_policy = "ACCEPT"` means any inbound traffic the rule set doesn't specifically deny is allowed by default — effectively an implicit-allow, fail-open posture. This is dangerous because it silently exposes any port/service that isn't explicitly blocked, including ports opened later by software updates, misconfigurations, or forgotten debug endpoints. A default-deny (`DROP`) posture is the standard security baseline: only traffic you've consciously allowed via explicit rules gets through, and anything new or unexpected is blocked until someone deliberately opens it. This "fail closed" behavior significantly reduces the blast radius of misconfigured services and unpatched ports.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `inbound_policy` attribute of the `linode_firewall` resource. The check expects the value to equal `"DROP"`. If `inbound_policy` is set to `"ACCEPT"` (or any value other than `DROP`), the check FAILS; if it is `"DROP"`, the check PASSES.

## Non-compliant example
```hcl
resource "linode_firewall" "web_fw" {
  label           = "web-firewall"
  inbound_policy  = "ACCEPT"
  outbound_policy = "DROP"

  inbound {
    label    = "allow-https"
    action   = "ACCEPT"
    protocol = "TCP"
    ports    = "443"
    ipv4     = ["0.0.0.0/0"]
  }
}
```

## Remediated example
```hcl
resource "linode_firewall" "web_fw" {
  label           = "web-firewall"
  inbound_policy  = "DROP"
  outbound_policy = "DROP"

  inbound {
    label    = "allow-https"
    action   = "ACCEPT"
    protocol = "TCP"
    ports    = "443"
    ipv4     = ["0.0.0.0/0"]
  }
}
```

## Remediation steps
1. Set `inbound_policy = "DROP"` on every `linode_firewall` resource.
2. Enumerate every service that legitimately needs inbound access (e.g. HTTPS on 443, SSH on a restricted CIDR) as explicit `inbound` rule blocks with `action = "ACCEPT"`.
3. Test the rule set in a staging environment before rolling out to production — a default-deny policy can break connectivity if a needed port was missed.
4. Periodically review the explicit allow rules to remove stale entries, since the risk of a fail-open default is otherwise reintroduced by an overly broad allow list.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/linode/firewall_inbound_policy.py)
- [Linode Terraform provider: linode_firewall](https://registry.terraform.io/providers/linode/linode/latest/docs/resources/firewall)
