# CKV_GCP_95: Ensure Memorystore for Redis has AUTH enabled
## Severity
**MEDIUM** (score: 5.0/10)

This detects Memorystore for Redis instances with AUTH disabled, meaning any client with network reachability can read and write cached data without any authentication whatsoever.

## Summary
This check requires `google_redis_instance` resources to set `auth_enabled = true`, so client connections to the Redis instance must present an AUTH token/password.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `google_redis_instance`
- **Check type:** resource (attribute-value check)

## Why it matters
By default, Redis has no authentication of its own — any client that can establish a network connection to the instance can issue arbitrary commands, including reading all cached data, flushing the entire dataset (`FLUSHALL`), or (depending on configuration) leveraging Redis commands for further compromise. Memorystore for Redis instances sit inside a VPC and are typically reachable by any workload on that network; without `auth_enabled`, network-level access (a misconfigured firewall, a compromised adjacent VM, or a workload that shouldn't have Redis access but shares the VPC) is equivalent to full data-plane access. Enabling AUTH adds a required credential layer on top of network controls, so a network-level misconfiguration or a compromised low-privilege workload does not automatically grant full read/write/delete access to whatever session data, cache entries, or rate-limiting state the application stores in Redis.

## How Checkov evaluates this
The check (`MemorystoreForRedisAuthEnabled`, a `BaseResourceValueCheck`) inspects the `auth_enabled` attribute on `google_redis_instance`, expecting `true`. The code comment notes it explicitly "accounts for if key is present but is set to False."
- **PASS**: `auth_enabled = true`.
- **FAIL**: `auth_enabled` is absent or `false` (the default).

## Non-compliant example
```hcl
resource "google_redis_instance" "cache" {
  name           = "app-cache"
  tier           = "STANDARD_HA"
  memory_size_gb = 5
  region         = "us-central1"
  # auth_enabled not set -> AUTH disabled, no credential required
}
```

## Remediated example
```hcl
resource "google_redis_instance" "cache" {
  name           = "app-cache"
  tier           = "STANDARD_HA"
  memory_size_gb = 5
  region         = "us-central1"
  auth_enabled   = true
}
```

## Remediation steps
1. Set `auth_enabled = true` on the `google_redis_instance` resource.
2. After apply, retrieve the generated AUTH string via `google_redis_instance.auth_string` (a Terraform-managed sensitive output) and update application client configuration to supply it on connect.
3. Store the AUTH string in a secret manager (e.g., Secret Manager) rather than hardcoding it in application config or source control.
4. Enabling AUTH on an existing instance can typically be applied in-place but will interrupt existing unauthenticated client connections — coordinate a deploy window with clients that need to add the credential.
5. For defense in depth, also consider `transit_encryption_mode` (see CKV_GCP_97) so the AUTH token and cached data aren't sent in plaintext over the network.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/MemorystoreForRedisAuthEnabled.py
- GCP docs: https://cloud.google.com/memorystore/docs/redis/about-auth
