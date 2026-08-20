# CKV_TC_9: Ensure Tencent Cloud MySQL instances do not enable access from public networks

## Severity
**CRITICAL** (score: 9.1/10)

Enabling internet access on a managed MySQL instance exposes a database service directly to the public internet, creating a direct path for unauthenticated network access, brute-force, and exploitation attempts against a data-storing backend.

## Summary
This check fails when a Tencent Cloud MySQL (CDB) instance is configured with `internet_service` enabled, meaning the database is directly reachable from the public internet.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `tencentcloud_mysql_instance`
- **Check type:** resource check (single-attribute value check)

## Why it matters
Exposing a managed database instance directly to the public internet dramatically increases its attack surface. Even with authentication in place, an internet-facing database endpoint is a prime target for credential-stuffing, brute-force login attempts, and exploitation of any unpatched MySQL/CDB vulnerabilities. Database engines are not designed to be internet-facing services — they lack the hardening (rate limiting, WAF, DDoS protection) that public-facing application tiers typically have. Best practice is to keep database instances reachable only from within a VPC, via private IP, bastion hosts, or VPN/peering connections, and to use network ACLs/security groups to restrict access to known application subnets. A publicly reachable database instance is one of the most common root causes of data breaches in cloud misconfiguration incidents.

## How Checkov evaluates this
The check (`CDBInternetService`) is implemented as a `BaseResourceNegativeValueCheck`:
- It inspects the attribute path `internet_service/[0]` (i.e., the first element of the `internet_service` argument) on `tencentcloud_mysql_instance` resources.
- Its "forbidden value" list is `[1]`.
- If `internet_service` is set to `1` (enabled), the check **FAILS**.
- If `internet_service` is `0`, unset, or any other value, the check **PASSES**.

## Non-compliant example
```hcl
resource "tencentcloud_mysql_instance" "example" {
  instance_name     = "prod-mysql"
  mem_size          = 4000
  volume_size       = 100
  vpc_id            = tencentcloud_vpc.app.id
  subnet_id         = tencentcloud_subnet.app.id
  internet_service  = 1  # public network access enabled -- FAILS CKV_TC_9
}
```

## Remediated example
```hcl
resource "tencentcloud_mysql_instance" "example" {
  instance_name     = "prod-mysql"
  mem_size          = 4000
  volume_size       = 100
  vpc_id            = tencentcloud_vpc.app.id
  subnet_id         = tencentcloud_subnet.app.id
  internet_service  = 0  # private network access only -- PASSES CKV_TC_9
}
```

## Remediation steps
1. Set `internet_service = 0` on the `tencentcloud_mysql_instance` resource (or simply omit the attribute, since it defaults to disabled).
2. Ensure the instance is deployed inside a VPC/subnet (`vpc_id`/`subnet_id`) that application servers can reach privately.
3. If external access is genuinely required (e.g., for a third-party integration), use a bastion host, VPN, or Tencent Cloud's private connection/peering options instead of enabling public internet service directly on the database.
4. Restrict access further with Tencent Cloud security groups bound to the instance, limiting inbound traffic to only the necessary source IPs/subnets and the MySQL port.
5. Note: toggling `internet_service` may require a brief network reconfiguration on the instance; test in a non-production environment first.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/tencentcloud/CDBInternetService.py)
