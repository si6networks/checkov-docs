# CKV_AWS_202: Ensure MemoryDB data is encrypted in transit
## Severity
**LOW** (score: 2.0/10)

Disabling TLS on MemoryDB lets client-cluster traffic travel in plaintext, exposing potentially sensitive cached data and application state to network interception.

## Summary
Ensures that Amazon MemoryDB for Redis clusters have TLS (in-transit encryption) enabled, preventing plaintext Redis protocol traffic between clients and the cluster.

## Applicability
- **Terraform**: `aws_memorydb_cluster` — inspects the `tls_enabled` attribute.

## Why it matters
Redis's native wire protocol is plaintext by default. If `tls_enabled` is `false` on a MemoryDB cluster, all traffic between application clients and the cluster — including `AUTH` passwords (if using Redis AUTH/ACL), cached session data, and any application data stored/retrieved — travels unencrypted across the network. This is exploitable by:
- Anyone with network visibility inside the VPC (a compromised instance, a misconfigured security group allowing broader access, or a malicious insider with network access) performing passive packet capture to harvest credentials or sensitive cached data.
- Lateral movement scenarios where an attacker who has compromised one workload in the VPC can sniff traffic to/from MemoryDB without needing to compromise the database itself.

Because MemoryDB is frequently used for session tokens, feature flags with sensitive gating logic, and application-level caches of query results (which may include PII), in-transit protection matters even within a "trusted" VPC boundary — defense in depth assumes the network can be compromised.

## How Checkov evaluates this
`MemoryDBClusterIntransitEncryption` is a `BaseResourceNegativeValueCheck` on `tls_enabled` with a forbidden value of `False`:
- If `tls_enabled` is explicitly `false` → FAIL.
- If `tls_enabled` is `true` or omitted (MemoryDB defaults `tls_enabled` to `true` at the API level) → PASS.

## Non-compliant example
```hcl
resource "aws_memorydb_cluster" "sessions" {
  name              = "session-cache"
  node_type         = "db.r6g.large"
  num_shards        = 2
  acl_name          = "open-access"
  subnet_group_name = aws_memorydb_subnet_group.main.name
  tls_enabled       = false   # FAILS CKV_AWS_202
}
```

## Remediated example
```hcl
resource "aws_memorydb_cluster" "sessions" {
  name              = "session-cache"
  node_type         = "db.r6g.large"
  num_shards        = 2
  acl_name          = "open-access"
  subnet_group_name = aws_memorydb_subnet_group.main.name
  tls_enabled       = true   # fix: enforce TLS in transit
}
```

## Remediation steps
1. Set `tls_enabled = true` (or simply omit the attribute, since MemoryDB defaults to TLS enabled).
2. Update application clients to connect using `rediss://` (TLS) endpoints and to trust the appropriate CA bundle for MemoryDB's certificate chain.
3. `tls_enabled` cannot be changed on an existing cluster without replacement — Terraform will force a new resource, so plan a cutover (new cluster + client reconfiguration) rather than expecting an in-place update.
4. Combine with `aws_memorydb_acl`/Redis ACL users requiring `AUTH` for defense in depth beyond transport encryption alone.
5. Verify client libraries and connection pool settings support TLS handshake overhead without breaking latency-sensitive paths; test in a non-production cluster first.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/MemoryDBClusterIntransitEncryption.py
- AWS docs: https://docs.aws.amazon.com/memorydb/latest/devguide/in-transit-encryption.html
