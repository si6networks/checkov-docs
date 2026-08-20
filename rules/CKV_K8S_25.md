# CKV_K8S_25: Minimize the admission of containers with added capability
## Severity
**LOW** (score: 2.0/10)

Allowing containers to add capabilities beyond the default set (e.g. SYS_ADMIN, SYS_PTRACE) significantly expands the container's attack surface for kernel-level exploitation and host breakout.

## Summary
This check fails any container that adds Linux capabilities via `securityContext.capabilities.add`, because adding capabilities beyond the container runtime's minimal default set expands what a compromised process inside the container can do to the kernel and host.

## Applicability
- **IaC framework:** Kubernetes manifests (YAML/JSON) and Terraform
- **Resource/entity types (Kubernetes):** `Pod`, `PodTemplate`, `Deployment`, `DeploymentConfig`, `ReplicaSet`, `ReplicationController`, `StatefulSet`, `DaemonSet`, `Job`, `CronJob`
- **Resource/entity types (Terraform):** `kubernetes_pod`, `kubernetes_pod_v1`, `kubernetes_deployment`, `kubernetes_deployment_v1`

## Why it matters
Linux capabilities decompose root privileges into distinct units (e.g. `NET_ADMIN`, `SYS_PTRACE`, `SYS_MODULE`, `DAC_OVERRIDE`). Container runtimes drop most capabilities by default, retaining only a small safe baseline. Any capability a container explicitly `add`s reintroduces a specific slice of root-equivalent power: `SYS_ADMIN` grants a very broad set of privileged operations nearly equivalent to full privileged mode; `SYS_PTRACE` lets a process attach to and inspect/modify the memory of other processes (including in other containers sharing a PID namespace); `NET_ADMIN` allows manipulating routing tables, firewall rules, and packet capture; `DAC_OVERRIDE`/`DAC_READ_SEARCH` bypass normal file permission checks entirely. If application code with an added capability is compromised (e.g. through a vulnerable dependency or injection flaw), the attacker directly inherits that capability, often enabling container escape, host network tampering, or unauthorized access to other workloads' data — a strictly larger blast radius than the same vulnerability in a container running with default capabilities.

## How Checkov evaluates this
- **Kubernetes-native (`AllowedCapabilities`):** for each container, checks `securityContext.capabilities.add`. If present and non-empty, FAILED. Absent or empty → PASSED.
- **Terraform:** inspects `spec[0].container[*].security_context[0].capabilities[0].add` (following `template[0].spec[0]` for Deployments). Fails if the `add` list is present and non-empty.

## Non-compliant example
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cerebro-prod
spec:
  template:
    spec:
      containers:
        - name: cerebro
          image: myorg/cerebro:1.0
          securityContext:
            capabilities:
              add: ["NET_ADMIN", "SYS_PTRACE"]
```

## Remediated example
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cerebro-prod
spec:
  template:
    spec:
      containers:
        - name: cerebro
          image: myorg/cerebro:1.0
          securityContext:
            capabilities:
              drop: ["ALL"]
              # no 'add' -> runs with the minimal default capability set
```

## Remediation steps
1. Remove `securityContext.capabilities.add` from the `cerebro-$ENV` Deployment in `src/cloud/frontend/cerebro/magna_k8s/k8s.yml`, and pair it with `capabilities.drop: ["ALL"]` to also achieve CKV_K8S_28's NET_RAW-drop requirement.
2. Determine why each added capability was requested — if the application needs raw socket access for ICMP pings, prefer a narrowly scoped `NET_RAW` grant only where truly required rather than broader capabilities like `NET_ADMIN`/`SYS_ADMIN`; if it needs to trace/debug other processes, question whether that functionality belongs in production at all.
3. Test the workload with capabilities removed in a staging environment — functionality that silently depended on an added capability (e.g. binding low ports, raw sockets, kernel module operations) will fail and need an alternative (e.g. binding a high port behind a Service, or moving privileged functionality to a dedicated, isolated component).
4. Enforce via Pod Security Admission `restricted` profile (which permits only `NET_BIND_SERVICE` to be added, dropping everything else) or an OPA/Kyverno policy allow-listing specific capabilities per namespace.

## References
- [Checkov check source (Kubernetes)](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/AllowedCapabilities.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/kubernetes/AllowedCapabilities.py)
- [Kubernetes: Configure a Security Context for a Pod or Container — Capabilities](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container)
