# CKV_K8S_2: Do not admit privileged containers (PodSecurityPolicy)
## Severity
**HIGH** (score: 7.5/10)

A PodSecurityPolicy that admits privileged containers removes the cluster-wide guardrail against unrestricted host access, allowing any workload under that policy to fully compromise the node.

## Summary
This check fails any `PodSecurityPolicy` that sets `spec.privileged: true`, because such a policy would allow the cluster to admit pods running fully privileged (host-equivalent) containers.

## Applicability
**Checkov framework(s):** `kubernetes`, `terraform`

- **IaC framework:** Kubernetes manifests (YAML/JSON) and Terraform
- **Resource/entity types:** `PodSecurityPolicy` (Kubernetes), `kubernetes_pod_security_policy` (Terraform)

## Why it matters
`PodSecurityPolicy` (PSP — deprecated and removed as of Kubernetes 1.25 in favor of Pod Security Admission) is a cluster-wide admission control object that defines what security-sensitive settings pods are *allowed* to request. When a PSP's `spec.privileged` is `true`, it permits any pod bound to that policy (via RBAC) to run with `securityContext.privileged: true`, i.e. with almost unrestricted host access — full device access, capability set, and typically the ability to escape container isolation entirely. A permissive PSP effectively acts as a blanket authorization for privileged workloads across every namespace/user that can use it, multiplying the blast radius of CKV_K8S_16 (container-level `privileged`) at the policy level: one misconfigured PSP can open the door to privileged containers cluster-wide rather than just in a single manifest.

## How Checkov evaluates this
The check (`PrivilegedContainersPSP`, using `BaseSpecOmittedOrValueCheck` for the Kubernetes-native check, and a direct `BaseResourceCheck` for Terraform) inspects `spec.privileged` on the `PodSecurityPolicy` object:
- **Kubernetes-native:** fails if `spec.privileged` is present and set to a disallowed (truthy) value; the base class treats omission as compliant.
- **Terraform:** fails specifically when `spec[0].privileged == [True]`.

## Non-compliant example
```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: legacy-permissive-psp
spec:
  privileged: true
  seLinux:
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
  name: restricted-psp
spec:
  privileged: false
  seLinux:
    rule: RunAsAny
  runAsUser:
    rule: MustRunAsNonRoot
  fsGroup:
    rule: MustRunAs
    ranges:
      - min: 1
        max: 65535
  volumes:
    - configMap
    - emptyDir
    - secret
    - persistentVolumeClaim
```

## Remediation steps
1. Set `spec.privileged: false` (or omit it, since `false` is the default) on all `PodSecurityPolicy` objects.
2. Since PSP is deprecated/removed in Kubernetes 1.25+, migrate to Pod Security Admission (namespace labels selecting `restricted`/`baseline`/`privileged` profiles) or a third-party policy engine (Kyverno, OPA/Gatekeeper) as the long-term replacement — do not invest further in PSP-only hardening if you're on a modern cluster.
3. Audit RoleBindings/ClusterRoleBindings that grant `use` verb on this PSP to confirm only intended, narrowly-scoped subjects (e.g. specific infra service accounts) could ever be bound to a privileged policy, if one is truly required.
4. If a privileged policy is genuinely required for specific infrastructure workloads, isolate it to a dedicated PSP bound only to those specific ServiceAccounts, never to a broad group or `system:authenticated`.

## References
- [Checkov check source (Kubernetes)](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/PrivilegedContainersPSP.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/kubernetes/PrivilegedContainerPSP.py)
- [Kubernetes: Pod Security Policies (deprecated)](https://kubernetes.io/docs/concepts/security/pod-security-policy/)
- [Kubernetes: Pod Security Admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/)
