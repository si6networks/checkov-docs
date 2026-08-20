# CKV_GCP_13: Ensure client certificate authentication to Kubernetes Engine Clusters is disabled

## Severity
**LOW** (score: 2.0/10)

Leaving client certificate authentication enabled on a GKE cluster retains a legacy, less-secure authentication path to the Kubernetes API server alongside modern auth, widening the attack surface for cluster credential compromise.

## Summary
This check requires GKE clusters to disable legacy client-certificate-based authentication (`master_auth.client_certificate_config.issue_client_certificate` must be `false`), forcing cluster access to rely on stronger, centrally-managed authentication mechanisms instead.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `google_container_cluster`
- **Check type:** resource (value check)

## Why it matters
GKE historically supported issuing a static client certificate as one of the ways to authenticate `kubectl`/API clients to the cluster's control plane. Client certificates have several security weaknesses compared to modern authentication (OIDC via Google identity, IAM-based authentication, or short-lived tokens):
- They are long-lived credentials — once issued, a client certificate typically remains valid for the lifetime of the cluster and cannot easily be revoked individually (revocation for a single compromised cert without affecting others is not readily supported).
- If a client certificate is exfiltrated (e.g. from a laptop, CI runner, or backup), an attacker gains persistent cluster-admin-equivalent access to the Kubernetes API server that is very difficult to detect or invalidate without significant disruption (rotating cluster credentials).
- Certificate-based auth bypasses centralized IAM logging/auditing and Cloud Identity-based access reviews, making it harder to track "who did what" compared to Google-identity-based authentication, which integrates with Cloud Audit Logs and can be centrally revoked/rotated via IAM.

Disabling `issue_client_certificate` removes this weaker, harder-to-revoke authentication path entirely, pushing all cluster access through GCP IAM / Google authentication, which supports centralized session/credential lifecycle management, MFA, and conditional access policies.

## How Checkov evaluates this
This is a `BaseResourceValueCheck`:
- **Inspected key:** `master_auth/[0]/client_certificate_config/[0]/issue_client_certificate`
- **Expected value:** `false`
- **PASS** if `issue_client_certificate` is explicitly `false`.
- **FAIL** if it is `true`, or (depending on the base check's handling of missing values) if the nested `master_auth.client_certificate_config` block/attribute is not set to `false` — always verify the value explicitly rather than relying on implicit provider defaults, since older provider versions issued a client certificate by default when the block was omitted.

## Non-compliant example
```hcl
resource "google_container_cluster" "sim_cluster" {
  name     = "sim-cluster"
  location = "us-central1"

  master_auth {
    client_certificate_config {
      issue_client_certificate = true
    }
  }
}
```

## Remediated example
```hcl
resource "google_container_cluster" "sim_cluster" {
  name     = "sim-cluster"
  location = "us-central1"

  master_auth {
    client_certificate_config {
      issue_client_certificate = false  # <-- changed from true
    }
  }
}
```

## Remediation steps
1. Set `master_auth.client_certificate_config.issue_client_certificate = false` on every `google_container_cluster` resource.
2. Ensure your team's `kubectl` access instead relies on `gcloud container clusters get-credentials`, which uses the GKE Auth Plugin / Google identity tokens rather than static certificates.
3. This setting is generally only applied at cluster creation time in older provider/API behavior — check whether changing it on an existing cluster requires cluster recreation in your provider version, and plan a maintenance window if so.
4. After disabling, audit any existing tooling, CI pipelines, or scripts that may still reference a previously-issued client certificate/kubeconfig, and migrate them to IAM-based authentication (e.g. Workload Identity for in-cluster workloads, or service-account-based `gcloud auth` for CI).
5. Pair this with disabling basic authentication (username/password) on the cluster and enabling Kubernetes RBAC combined with GKE's IAM integration for a fully centralized auth model.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GKEClientCertificateDisabled.py)
- [Terraform `google_container_cluster` — master_auth](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#client_certificate_config)
- [GKE authentication overview](https://cloud.google.com/kubernetes-engine/docs/how-to/api-server-authentication)
