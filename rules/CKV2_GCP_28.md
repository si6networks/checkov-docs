# CKV2_GCP_28: Ensure Vertex AI workbench instances are private
## Severity
**MEDIUM** (score: 5.0/10)

Assigning a public IP to a Vertex AI Workbench instance exposes a compute host that typically holds ML code, credentials, and training data directly to the internet, materially widening the network attack surface.

## Summary
This check ensures that Vertex AI Workbench instances are configured with `disable_public_ip = true`, so they do not receive a publicly routable IP address.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_workbench_instance`

## Why it matters
A Vertex AI Workbench instance with a public IP is directly reachable from the internet, exposing its Jupyter interface, SSH access surface, and any locally running services to external scanning and attack attempts. Notebook environments commonly contain embedded service-account credentials, dataset access, and unreviewed dependencies (arbitrary pip/conda packages), making them an attractive target: a compromised, internet-facing notebook instance can be used as a pivot point into the rest of the GCP project via its attached service account. Keeping the instance private (accessible only via internal networking, VPN, Identity-Aware Proxy, or bastion) enforces network-level defense-in-depth on top of any IAM/authentication controls the notebook interface provides.

## How Checkov evaluates this
This is a Terraform graph-based check (single attribute check) on `google_workbench_instance`:
- **PASS** if `gce_setup.disable_public_ip` is set to `true`.
- **FAIL** if the attribute is absent (defaults to allowing a public IP) or set to `false`.

## Non-compliant example
```hcl
resource "google_workbench_instance" "instance" {
  name     = "my-workbench"
  location = "us-central1-a"

  gce_setup {
    machine_type = "n1-standard-4"
    # disable_public_ip not set -> instance gets a public IP
  }
}
```

## Remediated example
```hcl
resource "google_workbench_instance" "instance" {
  name     = "my-workbench"
  location = "us-central1-a"

  gce_setup {
    machine_type       = "n1-standard-4"
    disable_public_ip  = true

    network_interfaces {
      network = google_compute_network.vpc.id
      subnet  = google_compute_subnetwork.subnet.id
    }
  }
}
```

## Remediation steps
1. Set `gce_setup.disable_public_ip = true` on the `google_workbench_instance` resource.
2. Ensure the instance's VPC/subnet has a route to the internet via Cloud NAT if the notebook needs outbound access (e.g., to install packages), since it will no longer have a direct public IP.
3. Provide access to data scientists via Identity-Aware Proxy (IAP) TCP forwarding, a bastion host, or Cloud VPN/Interconnect rather than a public IP.
4. This attribute is typically set at instance creation and may require replacing an existing public instance to apply.
5. Verify firewall rules still permit the necessary internal traffic (IAP forwarding range, VPC peering) after removing the public IP.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/gcp/GCPVertexWorkbenchInstanceNoPublicIp.json
- GCP docs: https://cloud.google.com/vertex-ai/docs/workbench/instances/create-console#network
