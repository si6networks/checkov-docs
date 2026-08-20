# CKV2_OCI_3: Ensure Kubernetes engine cluster is configured with NSG(s)

## Severity
**MEDIUM** (score: 5.0/10)

An OKE cluster endpoint without Network Security Groups lacks fine-grained network segmentation controls, increasing exposure to unwanted traffic but not by itself granting access or disclosing data.

## Summary
This check ensures an OCI Container Engine for Kubernetes (OKE) cluster's `endpoint_config` specifies at least one Network Security Group (NSG) ID, so that access to the Kubernetes API endpoint is governed by explicit network security rules.

## Applicability
Terraform. Applies to the `oci_containerengine_cluster` resource, specifically its `endpoint_config.nsg_ids` attribute.

## Why it matters
The Kubernetes API server endpoint is the control plane of the cluster — anyone who can reach it and authenticate can create/modify/delete any cluster resource, including deploying malicious workloads or exfiltrating secrets. Without an NSG attached to the cluster's API endpoint (`endpoint_config`), network-level access control relies solely on whatever broader subnet/security-list rules exist, which are often looser and shared across many other resources in the VCN. Attaching a dedicated NSG lets you scope exactly which hosts/CIDRs (e.g. only the corporate network, VPN, or CI/CD runners) may reach the Kubernetes API, providing defense-in-depth against exposing the control plane broadly and reducing the attack surface for control-plane-focused attacks (credential stuffing against the API server, exploiting unpatched Kubernetes API vulnerabilities, etc.).

## How Checkov evaluates this
Graph-based JSON policy (`OCI_KubernetesEngineClusterEndpointConfigWithNSG.json`). It requires ALL of the following to be true for the `oci_containerengine_cluster` resource to pass:
1. `endpoint_config.nsg_ids` attribute exists.
2. Its value is not (case-insensitive) the string `"null"`.
3. The value is not empty (`is_not_empty`).
4. The word count of the value is not equal to 0 (`number_of_words_not_equals: 0`).
It fails if `endpoint_config.nsg_ids` is missing, null, or an empty list — meaning no NSG is attached to the cluster endpoint.

## Non-compliant example
```hcl
resource "oci_containerengine_cluster" "oke" {
  compartment_id     = var.compartment_id
  kubernetes_version = "v1.28.2"
  name               = "prod-oke"
  vcn_id             = oci_core_vcn.main.id

  endpoint_config {
    subnet_id                 = oci_core_subnet.oke_endpoint.id
    is_public_ip_enabled      = false
    # no nsg_ids configured - API endpoint relies only on subnet-level security lists
  }
}
```

## Remediated example
```hcl
resource "oci_core_network_security_group" "oke_api_nsg" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.main.id
  display_name   = "oke-api-endpoint-nsg"
}

resource "oci_core_network_security_group_security_rule" "oke_api_allow_corp" {
  network_security_group_id = oci_core_network_security_group.oke_api_nsg.id
  direction                 = "INGRESS"
  protocol                  = "6"
  source                    = "203.0.113.0/24"
  source_type               = "CIDR_BLOCK"

  tcp_options {
    destination_port_range {
      min = 6443
      max = 6443
    }
  }
}

resource "oci_containerengine_cluster" "oke" {
  compartment_id     = var.compartment_id
  kubernetes_version = "v1.28.2"
  name               = "prod-oke"
  vcn_id             = oci_core_vcn.main.id

  endpoint_config {
    subnet_id            = oci_core_subnet.oke_endpoint.id
    is_public_ip_enabled = false
    nsg_ids              = [oci_core_network_security_group.oke_api_nsg.id]
  }
}
```

## Remediation steps
1. Create a dedicated `oci_core_network_security_group` for the OKE cluster's API endpoint.
2. Add `oci_core_network_security_group_security_rule` entries permitting only the specific source CIDRs (VPN, CI/CD runners, admin bastions) that need to reach the Kubernetes API port (default 6443).
3. Set `endpoint_config.nsg_ids` on the `oci_containerengine_cluster` resource to reference the new NSG's OCID.
4. If the cluster already exists, note that changing `endpoint_config` may require recreating the cluster or its node pools depending on the OCI provider version — test in a non-production environment first.
5. Combine this with `is_public_ip_enabled = false` (private endpoint) where feasible for defense-in-depth.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/oci/OCI_KubernetesEngineClusterEndpointConfigWithNSG.json
