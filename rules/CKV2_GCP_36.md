# CKV2_GCP_36: Ensure Vertex AI runtime is private

## Severity
**MEDIUM** (score: 5.0/10)

A Vertex AI runtime with a public IP is directly reachable from the internet, exposing a notebook execution environment (with attached credentials and data access) to network-based attacks.

## Summary
This check ensures that a Google Cloud Vertex AI (Notebooks) runtime's virtual machine is configured to use only an internal IP address, preventing it from being directly reachable from the public internet.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `google_notebooks_runtime`

This is a graph-based check (Checkov "graph check", defined as JSON) rather than a Python check.

## Why it matters
Vertex AI Workbench/Notebooks runtimes run Jupyter-based environments that typically have access to sensitive data, service account credentials, and internal APIs. If the runtime's VM is assigned a public/external IP address, it becomes directly reachable from the internet, expanding the attack surface: an attacker could attempt to exploit the Jupyter service, brute-force any exposed authentication, or pivot through the instance into the internal GCP network. Restricting the runtime to an internal IP only (`internal_ip_only = true`) forces all access through private connectivity (VPC, VPN, Interconnect, or IAP tunneling), which is far harder for an external attacker to reach and keeps the notebook's traffic within the organization's controlled network boundary.

## How Checkov evaluates this
The check inspects the Terraform resource `google_notebooks_runtime` for the attribute path `virtual_machine.virtual_machine_config.internal_ip_only`. Using the `jsonpath_equals` operator, the check **passes** only if this attribute is explicitly set to `"true"`. If the attribute is absent, or set to `false`, the check **fails**.

## Non-compliant example
```hcl
resource "google_notebooks_runtime" "insecure" {
  name     = "my-notebook-runtime"
  location = "us-central1"

  virtual_machine {
    virtual_machine_config {
      machine_type   = "n1-standard-4"
      internal_ip_only = false
    }
  }
}
```

## Remediated example
```hcl
resource "google_notebooks_runtime" "secure" {
  name     = "my-notebook-runtime"
  location = "us-central1"

  virtual_machine {
    virtual_machine_config {
      machine_type     = "n1-standard-4"
      internal_ip_only = true
    }
  }
}
```

## Remediation steps
1. Set `internal_ip_only = true` inside the `virtual_machine_config` block of the `google_notebooks_runtime` resource.
2. Ensure a VPC/subnet and any necessary Private Google Access or Private Service Connect configuration is in place so the runtime can still reach Google APIs without a public IP.
3. Provide access to end users via IAP (Identity-Aware Proxy) TCP forwarding, a bastion host, or VPN rather than direct public exposure.
4. This attribute is generally set at creation time; changing it on an existing runtime may require recreating the resource.
5. Combine with firewall rules restricting ingress to only known internal ranges for defense in depth.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/gcp/GCPVertexRuntimePrivate.json
- Google Cloud docs: https://cloud.google.com/vertex-ai/docs/workbench/instances/create-secure
