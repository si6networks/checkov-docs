# CKV_K8S_24: Do not allow containers with added capability (PodSecurityPolicy)
## Severity
**LOW** (score: 2.0/10)

A PodSecurityPolicy that permits adding arbitrary Linux capabilities lets workloads acquire powerful capabilities such as SYS_ADMIN or NET_ADMIN that are frequently used to escape container isolation entirely.

## Summary
This check fails any `PodSecurityPolicy` that sets `spec.allowedCapabilities` to a non-empty list, because that permits pods bound to the policy to add Linux capabilities beyond the container runtime's default set.

## Applicability
**Checkov framework(s):** `kubernetes`, `terraform`

- **IaC framework:** Kubernetes manifests (YAML/JSON) and Terraform
- **Resource/entity types:** `PodSecurityPolicy` (Kubernetes), `kubernetes_pod_security_policy` (Terraform)

## Why it matters
Linux capabilities break up the traditional root/non-root binary permission model into fine-grained privileges (e.g. `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`). Container runtimes drop most capabilities by default and only grant a minimal safe subset. A `PodSecurityPolicy` with a non-empty `allowedCapabilities` list authorizes any pod using that policy to request additional capabilities beyond that safe default — and depending on which capabilities are allowed, this can be as dangerous as full root: `CAP_SYS_ADMIN` alone provides many of the same abilities as running privileged, `CAP_NET_ADMIN` allows manipulating host/pod network configuration and packet capture, and `CAP_DAC_OVERRIDE`/`CAP_DAC_READ_SEARCH` bypass filesystem permission checks. Because this is a policy-level (not per-pod) authorization, one overly permissive PSP can grant this dangerous capability expansion to every workload bound to it across a namespace or cluster, similar in scope-multiplying risk to CKV_K8S_2's privileged flag.

## How Checkov evaluates this
- **Kubernetes-native (`AllowedCapabilities`):** checks `spec.allowedCapabilities` on the `PodSecurityPolicy`. If present and non-empty, FAILED; if absent or empty, PASSED.
- **Terraform (`AllowedCapabilitiesPSP`, a `BaseResourceNegativeValueCheck`):** inspects `spec[0].allowed_capabilities`; the forbidden value is `ANY_VALUE` (i.e. any value set at all triggers FAILED), meaning the attribute must be omitted entirely to pass.

## Non-compliant example
```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: net-tools-psp
spec:
  privileged: false
  allowedCapabilities:
    - NET_ADMIN
    - SYS_ADMIN
  runAsUser:
    rule: MustRunAsNonRoot
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
  # allowedCapabilities omitted entirely -> no capabilities beyond the runtime default may be added
  requiredDropCapabilities:
    - ALL
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
```

## Remediation steps
1. Remove `spec.allowedCapabilities` from `PodSecurityPolicy` objects, or leave it empty/unset.
2. Add `requiredDropCapabilities: ["ALL"]` so bound pods start from the most restrictive capability baseline, and require them to add back only what is strictly necessary via container-level `securityContext.capabilities.add` where genuinely needed (subject to CKV_K8S_25's per-container check).
3. Since PSP is deprecated/removed in Kubernetes 1.25+, plan migration to Pod Security Admission (which enforces "no added capabilities beyond an allowed list" under the `restricted` profile) or Kyverno/OPA Gatekeeper policies as the durable long-term control.
4. If a specific capability (e.g. `NET_BIND_SERVICE`) is required by a class of workloads, create a narrowly scoped, separate PSP that allows only that specific capability, bound only to the ServiceAccounts that need it, rather than adding it to a broadly-used policy.

## References
- [Checkov check source (Kubernetes)](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/AllowedCapabilitiesPSP.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/kubernetes/AllowedCapabilitiesPSP.py)
- [Kubernetes: Pod Security Policies — Capabilities](https://kubernetes.io/docs/concepts/security/pod-security-policy/#capabilities)
