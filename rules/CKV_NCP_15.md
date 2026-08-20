# CKV_NCP_15: Ensure Load Balancer Target Group is not using HTTP

## Severity
**HIGH** (score: 7.0/10)

A load balancer target group using plain HTTP instead of HTTPS transmits application traffic between the LB and backend unencrypted, exposing it to interception or tampering on the network path.

## Summary
This check ensures that Naver Cloud Platform (NCP) Load Balancer target groups (`ncloud_lb_target_group`) do not use the plaintext `HTTP` protocol for backend communication.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `ncloud_lb_target_group`
- **Check type:** resource-configuration check (Python)

## Why it matters
The target group protocol determines how the load balancer communicates with the backend instances behind it. If this leg of the connection uses plaintext `HTTP`, traffic between the load balancer and the backend server travels unencrypted across the internal network — even if the client-facing listener uses HTTPS/TLS, that only protects the client-to-LB segment. On a shared or multi-tenant internal network, an attacker with any foothold on that network segment (a compromised neighboring VM, a misconfigured internal routing path, or an insider) can passively sniff or actively tamper with backend traffic, potentially capturing session tokens, internal API credentials, or sensitive application data assumed to be "internal only" and therefore treated as trusted. Requiring the target group itself to avoid HTTP closes this end-to-end encryption gap.

## How Checkov evaluates this
The check reads the `protocol` attribute of the `ncloud_lb_target_group` resource:
- If `protocol` is present and **not equal to** `["HTTP"]` (e.g., `HTTPS`, `TCP`, `PROXY_TCP`, etc.), the check **PASSES**.
- If `protocol` is present and equals `["HTTP"]`, the check **FAILS**.
- If `protocol` is absent entirely, the check **FAILS** (conservative default).

## Non-compliant example
```hcl
resource "ncloud_lb_target_group" "backend_tg" {
  name     = "backend-target-group"
  port     = 80
  protocol = "HTTP"
  vpc_no   = ncloud_vpc.main.vpc_no
}
```

## Remediated example
```hcl
resource "ncloud_lb_target_group" "backend_tg" {
  name     = "backend-target-group"
  port     = 443
  protocol = "HTTPS"
  vpc_no   = ncloud_vpc.main.vpc_no
}
```

## Remediation steps
1. Change the `ncloud_lb_target_group` `protocol` attribute from `HTTP` to `HTTPS` (or another non-HTTP protocol appropriate to the workload).
2. Deploy/renew a valid TLS certificate on the backend instances so they can terminate or forward HTTPS traffic from the load balancer.
3. Update the corresponding `ncloud_lb_listener` and health-check configuration (see `CKV_NCP_1`) to match the new protocol and port.
4. Re-test end-to-end connectivity, since backend applications listening only on port 80 will need to also (or instead) listen on the HTTPS port.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/ncp/LBTargetGroupUsingHTTPS.py)
- [Naver Cloud Terraform provider: ncloud_lb_target_group](https://registry.terraform.io/providers/NaverCloudPlatform/ncloud/latest/docs/resources/lb_target_group)
