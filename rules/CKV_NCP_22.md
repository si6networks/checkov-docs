# CKV_NCP_22: Ensure NKS control plane logging enabled for all log types

## Severity
**HIGH** (score: 7.0/10)

Disabling audit logging on the NKS control plane removes the record of API-server activity needed to detect and investigate unauthorized access or privilege abuse in the cluster.

## Summary
This check ensures that a Naver Kubernetes Service (NKS) cluster (`ncloud_nks_cluster`) has control-plane audit logging enabled, so administrative and API-level actions against the cluster are recorded.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `ncloud_nks_cluster` (primary implementation); the associated graph-check metadata in the Checkov source also references `ncloud_route_table` / `ncloud_subnet` connections, but the resource-level Python check (`NKSControlPlaneLogging.py`) — which matches this rule's documented policy — is what enforces the audit-logging requirement described here.
- **Check type:** resource-configuration attribute check (Python)

## Why it matters
Kubernetes control-plane audit logs are the primary forensic record of what happened against the API server: who authenticated, what resources were created/modified/deleted, and which RBAC permissions were exercised. Without audit logging enabled, a compromised credential, an over-privileged service account, or a malicious insider can create workloads, exfiltrate secrets, modify RBAC bindings, or tamper with running pods — and there will be no record to reconstruct the incident afterward. This is a critical gap for detection (you can't alert on anomalous API activity you don't log) and for compliance (most frameworks require audit trails for privileged infrastructure actions). Enabling control-plane logging, specifically the `audit` log type, ensures every API server interaction is captured for later review and automated threat detection.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects a nested key path on the `ncloud_nks_cluster` resource: `log/0/audit/0`, corresponding to the first `log` block's first `audit` sub-block entry. No custom expected value is overridden, so the base class's default truthy check applies — the check **PASSES** only if that nested `log { audit { ... } }` configuration is present/enabled, and **FAILS** if the `log`/`audit` block is missing or not truthy.

## Non-compliant example
```hcl
resource "ncloud_nks_cluster" "prod_cluster" {
  name           = "prod-cluster"
  k8s_version    = "1.27.3-nks.1"
  vpc_no         = ncloud_vpc.main.vpc_no
  subnet_no_list = [ncloud_subnet.k8s.id]
  # no log / audit block defined -> no control-plane audit trail
}
```

## Remediated example
```hcl
resource "ncloud_nks_cluster" "prod_cluster" {
  name           = "prod-cluster"
  k8s_version    = "1.27.3-nks.1"
  vpc_no         = ncloud_vpc.main.vpc_no
  subnet_no_list = [ncloud_subnet.k8s.id]

  log {
    audit {
      enabled = true
    }
  }
}
```

## Remediation steps
1. Add a `log` block with an `audit` sub-block to every `ncloud_nks_cluster` resource, and set it to enabled.
2. Route the resulting audit logs to a centralized, tamper-evident log store (e.g. NCP Cloud Log Analytics or an external SIEM) rather than leaving them only on the cluster.
3. Configure alerting on the audit log stream for high-risk actions (RBAC changes, secret access, exec into pods, privileged pod creation).
4. Verify log retention meets your compliance requirements — audit-only-enabled without adequate retention still leaves a forensic gap for delayed detection scenarios.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/ncp/NKSControlPlaneLogging.py)
- [Naver Cloud Terraform provider: ncloud_nks_cluster](https://registry.terraform.io/providers/NaverCloudPlatform/ncloud/latest/docs/resources/nks_cluster)
