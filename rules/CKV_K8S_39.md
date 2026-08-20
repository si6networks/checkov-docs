# CKV_K8S_39: Do not use the CAP_SYS_ADMIN linux capability

## Severity
**HIGH** (score: 7.5/10)

SYS_ADMIN is widely regarded as equivalent to root on the host and is a common vector for documented container-escape and privilege-escalation exploits, so explicitly adding it to a container is a direct path to host compromise.

## Summary
This check ensures containers do not explicitly add the `SYS_ADMIN` Linux capability via `securityContext.capabilities.add`.

## Applicability
- **Kubernetes manifests**: container-level check across kinds `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`.
- **Terraform**: resource types `kubernetes_pod`, `kubernetes_pod_v1`, `kubernetes_deployment`, `kubernetes_deployment_v1`, at `spec.container[].security_context.capabilities.add`.

## Why it matters
`CAP_SYS_ADMIN` is frequently described as "the new root" among Linux capabilities: it grants an enormous, loosely-defined range of privileged operations — mounting/unmounting filesystems, configuring namespaces, performing certain `ioctl` calls, manipulating kernel keyrings, and more — that individually and in combination are well known primitives for container-escape exploits. Granting `SYS_ADMIN` to a container substantially undermines the isolation the container boundary is supposed to provide, effectively giving a compromised container process most of the capabilities it would need to break out to the host or interfere with the kernel. Because its scope is so broad and used in so many historical escape CVEs, Checkov treats any explicit `add` of `SYS_ADMIN` as an automatic failure regardless of other hardening in place.

## How Checkov evaluates this
For each container, the check inspects `securityContext.capabilities.add`: if the list contains the string `SYS_ADMIN`, the check FAILS. If `SYS_ADMIN` is not present in `add` (or `securityContext`/`capabilities`/`add` is absent entirely), it PASSES.

## Non-compliant example
```yaml
apiVersion: apps/v1
kind: Pod
metadata:
  name: privileged-tool
spec:
  containers:
    - name: app
      image: myrepo/tool:1.0.0
      securityContext:
        capabilities:
          add:
            - SYS_ADMIN
```

## Remediated example
```yaml
apiVersion: apps/v1
kind: Pod
metadata:
  name: privileged-tool
spec:
  containers:
    - name: app
      image: myrepo/tool:1.0.0
      securityContext:
        capabilities:
          drop:
            - ALL
          # SYS_ADMIN removed; add only the specific narrow capability actually needed, if any
```

## Remediation steps
1. Remove `SYS_ADMIN` from `securityContext.capabilities.add`.
2. Identify the actual narrow operation the workload needs (e.g. mount management, cgroup manipulation) and grant only the specific, much narrower capability that covers it, if one exists (e.g. `SYS_RESOURCE`, `SYS_PTRACE`), rather than the broad `SYS_ADMIN`.
3. If the workload genuinely requires host-level mount/namespace control (e.g. a CSI driver, CNI plugin, or similar system-level daemonset), confine it to a dedicated, tightly-scoped node pool with additional compensating controls (node isolation, restricted scheduling, mandatory access control such as AppArmor/SELinux profiles) rather than deploying it broadly.
4. Re-run tests after removal — some tools (e.g. certain profiling/monitoring agents, legacy Docker-in-Docker setups) rely on `SYS_ADMIN` and will need re-architecting (e.g. gVisor/Kata for sandboxing, or a dedicated privileged node).

## References
- [Checkov check source (Kubernetes)](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/AllowedCapabilitiesSysAdmin.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/kubernetes/AllowedCapabilitiesSysAdmin.py)
- [Kubernetes docs: Configure a Security Context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
