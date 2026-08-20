# CKV2_OCI_6: Ensure Kubernetes Engine Cluster pod security policy is enforced

## Severity
**HIGH** (score: 7.5/10)

Without an enforced pod security policy, the OKE cluster's admission controller cannot block privileged, host-mounting, or otherwise dangerous pod specs, allowing container escapes and host-level compromise.

## Summary
This check ensures OCI Container Engine for Kubernetes (OKE) clusters enable the Pod Security Policy admission controller (`options.admission_controller_options.is_pod_security_policy_enabled`), so that pod specifications are validated against security policies before admission.

## Applicability
**Checkov framework(s):** `terraform`

Terraform. Applies to the `oci_containerengine_cluster` resource, specifically the `options.admission_controller_options.is_pod_security_policy_enabled` attribute.

## Why it matters
Without a Pod Security admission mechanism enforced, any user or ServiceAccount with permission to create pods can deploy workloads with dangerous configurations — privileged containers, host namespace sharing (`hostNetwork`, `hostPID`, `hostIPC`), host path volume mounts, or containers running as root with unrestricted capabilities. Any one of these can be leveraged to escape the container boundary and compromise the underlying node or the broader cluster: a privileged pod can access all host devices and effectively achieve root on the node, a `hostPath` mount can read/write arbitrary host files (including kubelet credentials), and `hostNetwork`/`hostPID` expose the node's network stack and process namespace to the container. Enforcing pod security policy (or its Kubernetes-version-appropriate successor, Pod Security Admission / PSA) at admission time closes off these escalation paths by rejecting non-compliant pod specs before they ever run, rather than relying on developers to self-police security settings.

## How Checkov evaluates this
Graph-based JSON policy (`OCI_K8EngineClusterPodSecPolicyEnforced.json`). It requires BOTH:
1. `options.admission_controller_options.is_pod_security_policy_enabled` attribute exists.
2. Its value equals (case-insensitive) `"true"`.
It fails if the attribute is missing or set to `false`.

## Non-compliant example
```hcl
resource "oci_containerengine_cluster" "oke" {
  compartment_id     = var.compartment_id
  kubernetes_version = "v1.28.2"
  name               = "prod-oke"
  vcn_id             = oci_core_vcn.main.id

  options {
    service_lb_subnet_ids = [oci_core_subnet.lb.id]
    # admission_controller_options not set - PSP admission controller disabled
  }
}
```

## Remediated example
```hcl
resource "oci_containerengine_cluster" "oke" {
  compartment_id     = var.compartment_id
  kubernetes_version = "v1.28.2"
  name               = "prod-oke"
  vcn_id             = oci_core_vcn.main.id

  options {
    service_lb_subnet_ids = [oci_core_subnet.lb.id]

    admission_controller_options {
      is_pod_security_policy_enabled = true
    }
  }
}
```

## Remediation steps
1. Add an `admission_controller_options` block under `options` on the `oci_containerengine_cluster` resource with `is_pod_security_policy_enabled = true`.
2. Note that upstream Kubernetes removed the `PodSecurityPolicy` API in v1.25+; verify which admission mechanism your OKE cluster version actually enforces when this flag is set, and plan a migration to Kubernetes' built-in Pod Security Admission (`restricted`/`baseline` namespace labels) or a policy engine like Kyverno/OPA Gatekeeper if running on newer Kubernetes versions.
3. Before enabling enforcement in production, audit existing workloads for privileged settings (`privileged: true`, `hostNetwork`, `hostPID`, `hostPath` volumes, running as root) that would be blocked, and remediate them first to avoid breaking existing deployments.
4. Roll out enforcement in a staging/non-production cluster first, then progressively apply to production namespaces.
5. Continuously monitor for policy violations/denied pod creations post-enablement to catch any workloads that still need updating.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/oci/OCI_K8EngineClusterPodSecPolicyEnforced.json
