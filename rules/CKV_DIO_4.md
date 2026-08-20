# CKV_DIO_4: Ensure the firewall ingress is not wide open

## Severity
**HIGH** (score: 8.0/10)

An inbound firewall rule sourced from 0.0.0.0/0 (or ::/0) opens the associated ports to the entire internet, removing network-layer segmentation and materially widening the attack surface for the resources behind it.

## Summary
This check fails a DigitalOcean Cloud Firewall (`digitalocean_firewall`) resource if any inbound rule allows traffic from `0.0.0.0/0` or `::/0` — i.e., from any IPv4 or IPv6 address on the internet.

## Applicability
Terraform resource type `digitalocean_firewall` (DigitalOcean provider). Specifically inspects each entry in the `inbound_rule` block list and its nested `source_addresses` attribute.

## Why it matters
An inbound firewall rule scoped to `0.0.0.0/0`/`::/0` exposes the associated port to literally any host on the internet, removing network-layer segmentation as a defense against exploitation. Even if the underlying service has its own authentication, this configuration means every unpatched vulnerability, misconfiguration, or default credential on that service is directly reachable by mass internet scanners and automated exploit bots — this is one of the most common root causes behind compromised cloud instances (databases, admin panels, SSH, RDP left open to the world). Restricting `source_addresses` to known CIDR ranges (office IPs, VPN egress, a load balancer's IP, or DigitalOcean VPC ranges) enforces defense-in-depth even when application-layer auth is also present.

## How Checkov evaluates this
The check (`FirewallIngressOpen`) reads the `inbound_rule` list from the resource config. For each rule, it examines the `source_addresses` list; for every source address entry, if the value is exactly `"0.0.0.0/0"` or `"::/0"`, the check immediately returns `FAILED`. If no inbound rule contains either of these wide-open CIDR values (or if there are no inbound rules at all), the check returns `PASSED`.

## Non-compliant example
```hcl
resource "digitalocean_firewall" "web" {
  name = "web-firewall"

  droplet_ids = [digitalocean_droplet.web.id]

  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }
}
```

## Remediated example
```hcl
resource "digitalocean_firewall" "web" {
  name = "web-firewall"

  droplet_ids = [digitalocean_droplet.web.id]

  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = ["203.0.113.0/24"]  # corporate VPN egress range
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "443"
    source_addresses = ["0.0.0.0/0", "::/0"]  # HTTPS: intentionally public
  }
}
```

## Remediation steps
1. Identify which inbound rule(s) use `0.0.0.0/0` or `::/0` in `source_addresses`.
2. For administrative/management ports (SSH 22, RDP 3389, database ports, internal APIs), replace the wide-open CIDR with specific known ranges (VPN exit IPs, bastion host IP, office IP block, or DigitalOcean VPC CIDR).
3. For ports that must be genuinely public (e.g., 80/443 on a public web server), this may be an accepted exception — if so, scope the Checkov suppression to just that rule with a documented justification rather than suppressing the whole resource.
4. Consider layering a bastion host, VPN, or DigitalOcean VPC network instead of exposing management ports directly to the internet at all.
5. Re-run `terraform plan`/`checkov` to confirm remaining rules pass, and audit any other firewalls/droplets that might already have overly permissive rules applied.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/digitalocean/FirewallIngressOpen.py
- DigitalOcean Terraform provider docs: https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/firewall
