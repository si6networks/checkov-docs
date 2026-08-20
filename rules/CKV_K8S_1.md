# CKV_K8S_1: Do not admit containers wishing to share the host process ID namespace
## Severity
**MEDIUM** (score: 5.0/10)

Allowing pods to share the host's PID namespace lets a compromised container observe and signal host and other-container processes, a well-known container-escape and privilege-escalation vector.

## Summary
This check ensures PodSecurityPolicy (PSP) resources do not permit pods to share the host's process ID (PID) namespace.

## Applicability
Applies to both raw Kubernetes manifests (`PodSecurityPolicy` kind, `spec.hostPID`) and Terraform configurations using the `kubernetes` provider (`kubernetes_pod_security_policy` resource, `spec[0].host_pid`). Corresponds to CIS Kubernetes Benchmark controls 1.7.2 (v1.3) / 5.2.2 (v1.5).

## Why it matters
When `hostPID: true` is permitted, a pod's containers share the host machine's PID namespace instead of getting an isolated one. This means processes inside the container can see — and, depending on other permissions, potentially signal, trace (`ptrace`), or interact with — every process running on the underlying node, including processes belonging to other pods and the host's own system processes (kubelet, container runtime, etc.). This is a significant container-escape and cross-tenant information-disclosure risk: a compromised or malicious container with host PID access can enumerate host processes, read process environment variables and command-line arguments (which often contain secrets), and in combination with other loosened settings (e.g., `SYS_PTRACE` capability), inject into or hijack other processes on the node. A PodSecurityPolicy that allows `hostPID` effectively permits any pod using that PSP to break container process isolation.

## How Checkov evaluates this
For the raw Kubernetes `PodSecurityPolicy` resource, `ShareHostPIDPSP` (a `BaseSpecOmittedOrValueCheck`) inspects `spec.hostPID`: the check fails when `hostPID` is present and set to `true`; it passes when the field is omitted or set to `false` (the base class's "omitted-or-value" logic treats an absent field as the safe default).

For the Terraform `kubernetes_pod_security_policy` resource, the equivalent check inspects `spec[0].host_pid`: it **PASSES** if the attribute is missing (`missing_block_result=PASSED`, i.e., defaults to not sharing host PID) or explicitly `false`; it **FAILS** if `host_pid` is explicitly `true`.

## Non-compliant example
```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: permissive-psp
spec:
  hostPID: true   # pods using this PSP can share the host PID namespace
  privileged: false
  seLinux:
    rule: RunAsAny
  runAsUser:
    rule: RunAsAny
  fsGroup:
    rule: RunAsAny
  supplementalGroups:
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
  hostPID: false  # fix: disallow sharing of the host PID namespace
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
  supplementalGroups:
    rule: MustRunAs
    ranges:
      - min: 1
        max: 65535
  volumes:
    - configMap
    - secret
    - emptyDir
```

## Remediation steps
1. Set `spec.hostPID: false` (or omit the field entirely) in every `PodSecurityPolicy`, and `host_pid = false` (or omit) in every Terraform `kubernetes_pod_security_policy` resource.
2. Audit workloads to identify why `hostPID` was requested in the first place — legitimate uses are rare and usually limited to specialized node-monitoring/debugging agents; most application workloads never need it.
3. If a specific workload genuinely needs host process visibility (e.g., a node-level monitoring DaemonSet), scope a separate, tightly restricted PSP (or, on clusters that have migrated off PSP, an equivalent Pod Security Admission `restricted`/`baseline` profile exception) to only that workload's service account, rather than allowing it broadly.
4. Note: PodSecurityPolicy is deprecated and removed as of Kubernetes v1.25 — if running v1.25+, this control must be enforced instead via Pod Security Admission (`restricted` or `baseline` profile) or an external policy engine (OPA/Gatekeeper, Kyverno) blocking `hostPID: true` at the Pod spec level directly.

## References
- [Checkov check source (Kubernetes)](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/ShareHostPIDPSP.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/kubernetes/ShareHostPIDPSP.py)
- [Kubernetes docs: Pod Security Policies (deprecated)](https://kubernetes.io/docs/concepts/security/pod-security-policy/)
- [Kubernetes docs: Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
