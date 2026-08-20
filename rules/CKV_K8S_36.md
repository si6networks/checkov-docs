# CKV_K8S_36: Minimize the admission of containers with capabilities assigned (PodSecurityPolicy)

## Severity
**LOW** (score: 2.0/10)

A PodSecurityPolicy that does not force-drop Linux capabilities allows any admitted pod to retain the default (or added) capability set, which can enable privilege escalation or host-level compromise from within a container that is otherwise assumed to be unprivileged.

## Summary
This check ensures a `PodSecurityPolicy` requires dropping Linux capabilities (`spec.requiredDropCapabilities`) rather than allowing pods to keep the default capability set.

## Applicability
**Checkov framework(s):** `kubernetes`, `terraform`

- **Kubernetes manifests**: resource kind `PodSecurityPolicy`, field `spec.requiredDropCapabilities`.
- **Terraform**: resource type `kubernetes_pod_security_policy`, attribute `spec[0].required_drop_capabilities`.

## Why it matters
Linux capabilities split up the privileges traditionally reserved for root (e.g. `NET_RAW` for raw sockets, `SYS_ADMIN` for a wide range of administrative operations, `SYS_MODULE` for loading kernel modules). By default, container runtimes grant containers a non-trivial baseline set of capabilities even when not running as root, several of which (`NET_RAW`, `NET_ADMIN`, `SYS_CHROOT`) provide meaningful post-compromise attack primitives — e.g., `NET_RAW` enables packet sniffing/spoofing on the pod network, useful for credential theft via ARP or traffic interception. A PodSecurityPolicy that doesn't require any capability drops means every pod admitted under it retains the full default capability set even if its own manifest never asks for anything special, silently expanding the effective attack surface across the whole fleet. Requiring drops (ideally `ALL`, with `add` used only for the few capabilities a specific workload actually needs) implements least privilege at the cluster admission layer instead of trusting every application author to configure it correctly.

## How Checkov evaluates this
- **Kubernetes check** (`MinimizeCapabilitiesPSP`): looks at `spec.requiredDropCapabilities`; if the key exists and is non-empty, PASS; otherwise FAIL.
- **Terraform check** (`MinimiseCapabilitiesPSP`): looks at `spec[0].required_drop_capabilities`; if truthy, PASS; otherwise FAIL.
Note this checks only that *some* capabilities are required to be dropped — it does not verify the list includes `ALL` (that finer-grained requirement is enforced at the container level by CKV_K8S_37).

## Non-compliant example
```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: example-psp
spec:
  privileged: false
  seLinux:
    rule: RunAsAny
  supplementalGroups:
    rule: RunAsAny
  runAsUser:
    rule: RunAsAny
  fsGroup:
    rule: RunAsAny
  volumes:
  - '*'
```

## Remediated example
```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: example-psp
spec:
  privileged: false
  requiredDropCapabilities:   # added
  - ALL
  seLinux:
    rule: RunAsAny
  supplementalGroups:
    rule: RunAsAny
  runAsUser:
    rule: RunAsAny
  fsGroup:
    rule: RunAsAny
  volumes:
  - '*'
```

## Remediation steps
1. Add `spec.requiredDropCapabilities: [ALL]` (or at minimum a list including the dangerous defaults like `NET_RAW`) to the PSP.
2. In Terraform, set `required_drop_capabilities = ["ALL"]` in the `spec` block of `kubernetes_pod_security_policy`.
3. If specific workloads need a capability back (e.g. `NET_BIND_SERVICE` to bind ports < 1024), use `spec.allowedCapabilities` on a narrowly-scoped PSP for just those workloads, keeping the broad default at `ALL` dropped.
4. On Kubernetes 1.25+ (PSP removed), enforce equivalent behavior via Pod Security Admission's `restricted` profile or an admission controller (Kyverno/OPA Gatekeeper) requiring `securityContext.capabilities.drop: [ALL]` at the container level.

## References
- [Checkov check source (Kubernetes)](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/MinimizeCapabilitiesPSP.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/kubernetes/MinimiseCapabilitiesPSP.py)
- [Kubernetes docs: Configure a Security Context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
