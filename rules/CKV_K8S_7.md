# CKV_K8S_7: Do not admit containers with the NET_RAW capability
## Severity
**LOW** (score: 2.0/10)

Failing to drop the NET_RAW capability lets a compromised container craft raw sockets for ARP/IP spoofing and packet sniffing, enabling network-level attacks against other workloads on the same node.

## Summary
This check fails a `PodSecurityPolicy` unless `spec.requiredDropCapabilities` includes either `ALL` or `NET_RAW`, ensuring pods admitted under the policy cannot retain the `NET_RAW` Linux capability.

## Applicability
**Checkov framework(s):** `kubernetes`, `terraform`

- **Kubernetes manifests**: `PodSecurityPolicy` kind.
- **Terraform**: `kubernetes_pod_security_policy` resource.

Note: PSP is removed in Kubernetes 1.25+; on newer clusters enforce this via Pod Security Admission or an admission controller (e.g., Kyverno/OPA) that drops capabilities instead.

## Why it matters
`NET_RAW` allows a process to open raw and packet sockets, which enables crafting arbitrary IP packets, ARP/ICMP spoofing, and running network sniffers (e.g., a compromised container running `tcpdump` or spoofing traffic on the pod network). By default, container runtimes historically kept `NET_RAW` in the default capability set for non-privileged containers (it's needed for things like `ping`). If it's not explicitly dropped, an attacker who compromises a container (e.g., via a vulnerable web app) can pivot to network-layer attacks against other pods sharing the network namespace/CNI, including spoofing traffic to bypass network policies that rely on source-IP trust. This maps to CIS Kubernetes Benchmark 1.7.7 (CIS-1.3) / 5.2.7 (CIS-1.5). Forcing `requiredDropCapabilities` to include `NET_RAW` (or the stronger `ALL`, then adding back only what's needed via `allowedCapabilities`) closes this off cluster-wide.

## How Checkov evaluates this
`DropCapabilitiesPSP.py` reads `spec.requiredDropCapabilities`:
- If it's a non-empty list and contains `"ALL"` **or** `"NET_RAW"` → PASSED.
- Otherwise (missing, empty, or containing neither) → FAILED.

Terraform equivalent checks `spec[0].required_drop_capabilities[0]` for the same condition.

## Non-compliant example
```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: no-drop-caps
spec:
  privileged: false
  runAsUser:
    rule: MustRunAsNonRoot
  # requiredDropCapabilities omitted -> NET_RAW retained -> FAILS
```

```hcl
resource "kubernetes_pod_security_policy" "no_drop_caps" {
  metadata {
    name = "no-drop-caps"
  }
  spec {
    privileged = false
    run_as_user {
      rule = "MustRunAsNonRoot"
    }
    # required_drop_capabilities omitted -> FAILS
  }
}
```

## Remediated example
```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: drop-net-raw
spec:
  privileged: false
  runAsUser:
    rule: MustRunAsNonRoot
  requiredDropCapabilities:
  - ALL   # drops NET_RAW along with every other unneeded capability
```

```hcl
resource "kubernetes_pod_security_policy" "drop_net_raw" {
  metadata {
    name = "drop-net-raw"
  }
  spec {
    privileged = false
    run_as_user {
      rule = "MustRunAsNonRoot"
    }
    required_drop_capabilities = ["ALL"]
  }
}
```

## Remediation steps
1. Set `requiredDropCapabilities: ["ALL"]` as the default posture, then use `allowedCapabilities` to add back only the specific capabilities a workload genuinely needs (e.g., `NET_BIND_SERVICE` for binding to low ports).
2. If dropping `ALL` breaks a legitimate workload, drop `NET_RAW` explicitly at minimum: `requiredDropCapabilities: ["NET_RAW"]`.
3. Audit any pods relying on raw sockets (e.g., diagnostic tools using `ping`/`traceroute`) and either move that tooling to a dedicated debug pod with an explicit `allowedCapabilities` grant, or run it as an ephemeral debug container.
4. On Kubernetes 1.25+, replace this with a Pod Security Standard (`baseline` or `restricted`) or an admission controller policy enforcing `securityContext.capabilities.drop: ["ALL"]` at the container level.
5. Re-scan with `checkov -d . --check CKV_K8S_7`.

## References
- [Checkov check source (Kubernetes)](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/DropCapabilitiesPSP.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/kubernetes/DropCapabilitiesPSP.py)
- [Kubernetes Pod Security Policy documentation](https://kubernetes.io/docs/concepts/policy/pod-security-policy/)
