# CKV_NCP_20: Ensure Routing Table associated with Web tier subnet have the default route (0.0.0.0/0) defined to allow connectivity

## Severity
**LOW** (score: 3.0/10)

This check verifies that a NAT-gateway default route exists for web-tier connectivity; a missing route is primarily an availability/connectivity gap rather than a direct confidentiality or integrity exposure.

## Summary
This check ensures that Naver Cloud Platform (NCP) route table entries (`ncloud_route`) pointing at a NAT Gateway (`target_type = "NATGW"`) use the default route destination `0.0.0.0/0`, so outbound internet connectivity is correctly and completely routed through the NAT gateway.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `ncloud_route`
- **Check type:** resource-configuration check (Python)

## Why it matters
This check is primarily a reliability/correctness control rather than a direct exploit-prevention one, but it has security implications: a NAT gateway route entry that targets a narrower destination CIDR than `0.0.0.0/0` will only route a subset of outbound traffic through the NAT gateway, while traffic to unlisted destinations either fails to route (breaking connectivity, e.g. for OS/security patch downloads, external API calls, or telemetry) or, in a misconfigured routing table with a conflicting broader rule elsewhere, could be inadvertently routed through an unintended path (e.g. directly to the internet bypassing the NAT gateway's logging/inspection, or through an unexpected peering/VPN path). Consistently pointing the default route at the NAT gateway ensures all "default" outbound traffic follows one well-understood, auditable egress path rather than being split unpredictably across multiple less-visible routes.

## How Checkov evaluates this
The check inspects `ncloud_route` resources:
- It only evaluates rules where both `destination_cidr_block` and `target_type` are present.
- If `target_type == ["NATGW"]`:
  - If `destination_cidr_block == ["0.0.0.0/0"]`, the check **PASSES**.
  - Otherwise (any other destination CIDR), the check **FAILS**.
- If `target_type` is not `NATGW`, or either key is missing, the check returns **UNKNOWN** (not evaluated — the rule doesn't apply, e.g. routes targeting an internet gateway or peering connection).

## Non-compliant example
```hcl
resource "ncloud_route" "web_nat_route" {
  route_table_no          = ncloud_route_table.web.id
  destination_cidr_block  = "10.0.0.0/16"
  target_type             = "NATGW"
  target_name             = ncloud_nat_gateway.main.name
  target_no               = ncloud_nat_gateway.main.id
}
```

## Remediated example
```hcl
resource "ncloud_route" "web_nat_route" {
  route_table_no          = ncloud_route_table.web.id
  destination_cidr_block  = "0.0.0.0/0"
  target_type             = "NATGW"
  target_name             = ncloud_nat_gateway.main.name
  target_no               = ncloud_nat_gateway.main.id
}
```

## Remediation steps
1. For every `ncloud_route` entry with `target_type = "NATGW"` on a route table associated with a web-tier (private-subnet-with-outbound-need) subnet, set `destination_cidr_block = "0.0.0.0/0"`.
2. Confirm there isn't a conflicting, more-specific route in the same route table that would unexpectedly override the default route for a subset of traffic.
3. If the intent really is to route only specific destination ranges through the NAT gateway (a legitimate but narrower use case), be aware this check assumes the "default outbound to internet via NAT" pattern and will flag narrower CIDRs as non-compliant — document any deliberate exception.
4. Validate outbound connectivity (package installs, external API calls, DNS resolution) from instances in the affected subnet after changing the route.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/ncp/RouteTableNATGatewayDefault.py)
- [Naver Cloud Terraform provider: ncloud_route](https://registry.terraform.io/providers/NaverCloudPlatform/ncloud/latest/docs/resources/route)
