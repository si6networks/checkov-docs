# CKV_K8S_4: Do not admit containers wishing to share the host network namespace

## Severity
**MEDIUM** (score: 5.0/10)

A PodSecurityPolicy allowing `hostNetwork: true` lets any admitted pod bind to the host's network interfaces and observe/intercept traffic and services bound to localhost, effectively breaking network isolation between the container and the underlying node cluster-wide.

## Summary
This check ensures a Kubernetes `PodSecurityPolicy` does not allow pods to use `hostNetwork: true`, which would let a pod share the host node's network namespace.

## Applicability
- **Kubernetes manifests**: resource kind `PodSecurityPolicy`, field `spec.hostNetwork`.
- **Terraform**: resource type `kubernetes_pod_security_policy`, attribute `spec[0].host_network`.

## Why it matters
`hostNetwork: true` removes the network namespace isolation between the pod and the underlying node. The pod's containers get direct access to the host's network interfaces, loopback address, and any service listening on `localhost` on that node (which is often assumed to be a trust boundary, e.g. local metrics endpoints, kubelet's read-only port, or node-level agents). It also lets the pod bind to host ports directly, which can be used to intercept traffic intended for other pods or to bypass NetworkPolicy enforcement (since traffic no longer traverses the pod network overlay in the same way). A compromised container with host networking can perform network reconnaissance and lateral movement against the node and other pods scheduled there far more easily than a normally-namespaced pod. This is why the check defaults to PASS when the field is absent (Kubernetes default is `false`) but fails hard when `true` is explicitly requested.

## How Checkov evaluates this
- **Kubernetes check** (`ShareHostNetworkNamespacePSP`, subclass of `BaseSpecOmittedOrValueCheck`): inspects `spec.hostNetwork`. Omitted or non-`true` values PASS; `hostNetwork: true` FAILS.
- **Terraform check** (`BaseResourceValueCheck`): inspects `spec[0].host_network`, expects value `False`. `missing_block_result` is `PASSED`, so an absent block also passes; only an explicit `host_network = true` FAILS.

## Non-compliant example
```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: example-psp
spec:
  hostNetwork: true
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
  hostNetwork: false   # pods must use their own network namespace
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

## Remediation steps
1. Remove `hostNetwork: true` from the PSP spec, or set it to `false`.
2. In Terraform, remove `host_network = true` from `kubernetes_pod_security_policy.spec`, or set it to `false`.
3. If a workload genuinely needs host networking (e.g. a CNI plugin daemonset, kube-proxy, or a monitoring agent that must see the host network), grant it via a dedicated, tightly-scoped PSP bound only to that workload's ServiceAccount — never as a cluster-wide default.
4. On Kubernetes 1.25+ where PSP is removed, enforce the equivalent restriction via Pod Security Admission (`baseline`/`restricted` profiles disallow `hostNetwork`) or an admission controller such as Kyverno/OPA Gatekeeper.

## References
- [Checkov check source (Kubernetes)](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/SharedHostNetworkNamespacePSP.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/kubernetes/SharedHostNetworkNamespacePSP.py)
- [Kubernetes docs: Pod Security Policies](https://kubernetes.io/docs/concepts/security/pod-security-policy/)
