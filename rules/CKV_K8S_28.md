# CKV_K8S_28: Minimize the admission of containers with the NET_RAW capability
## Severity
**LOW** (score: 2.0/10)

The NET_RAW capability lets a container craft raw/spoofed packets, enabling ARP spoofing and network sniffing attacks against other workloads, though it does not by itself grant host or root access.

## Summary
This check fails any container that does not explicitly drop the `NET_RAW` capability (or all capabilities via `ALL`), because `NET_RAW` allows a process to open raw sockets and spy on or forge network traffic on its network namespace.

## Applicability
**Checkov framework(s):** `kubernetes`, `terraform`

- **IaC framework:** Kubernetes manifests (YAML/JSON) and Terraform
- **Resource/entity types (Kubernetes):** `Pod`, `PodTemplate`, `Deployment`, `DeploymentConfig`, `ReplicaSet`, `ReplicationController`, `StatefulSet`, `DaemonSet`, `Job`, `CronJob`
- **Resource/entity types (Terraform):** `kubernetes_pod`, `kubernetes_pod_v1`, `kubernetes_deployment`, `kubernetes_deployment_v1`

## Why it matters
`NET_RAW` is retained by container runtimes in their default capability set (unlike most other capabilities, which are dropped by default), largely for legacy compatibility with tools like `ping`. However, `NET_RAW` allows a process to create raw and packet sockets, meaning it can craft arbitrary IP packets (including spoofed source addresses) and sniff all traffic visible on the container's network interface — this has been used in real-world attacks for ARP spoofing/poisoning within a shared network segment, TCP session hijacking via crafted packets, and bypassing certain network-layer access controls that assume well-formed, non-spoofed traffic. Because it's part of the default capability set, most containers unknowingly retain this ability unless it is explicitly dropped, making it one of very few practical, broadly-applicable "drop this by default" hardening steps recommended by CIS Kubernetes Benchmark 1.7.7 / 5.2.7.

## How Checkov evaluates this
- **Kubernetes-native (`DropCapabilities`):** for each container, checks `securityContext.capabilities.drop`. PASSED only if the drop list contains `"ALL"`, `"all"`, or `"NET_RAW"` (case variations for ALL are explicitly handled). Any container missing `securityContext`, `capabilities`, or a qualifying `drop` entry is FAILED.
- **Terraform (`DropCapabilities`):** inspects `spec[0].container[*].security_context[0].capabilities[0].drop` (following `template[0].spec[0]` for Deployments). Passes only if the drop list contains `"ALL"` or `"NET_RAW"`; missing `security_context`/`capabilities`/`drop` at any level is FAILED.

## Non-compliant example
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: observability-agent
spec:
  template:
    spec:
      containers:
        - name: agent
          image: myorg/agent:1.0
          securityContext: {}   # no capabilities.drop -> NET_RAW retained by default
```

## Remediated example
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: observability-agent
spec:
  template:
    spec:
      containers:
        - name: agent
          image: myorg/agent:1.0
          securityContext:
            capabilities:
              drop: ["ALL"]
```

## Remediation steps
1. Add `securityContext.capabilities.drop: ["ALL"]` to every container in the affected Deployments (`observability`, `dash`, `argo` bases/overlays), which drops `NET_RAW` along with every other non-essential capability in one step.
2. If dropping `ALL` breaks functionality that legitimately needs a specific capability (e.g. `NET_BIND_SERVICE` to bind a privileged port), add back only that specific capability via `capabilities.add` while keeping `NET_RAW` dropped.
3. If the workload genuinely needs raw sockets (e.g. a real ICMP-based health-check tool), scope that need to a dedicated, minimal sidecar rather than granting it to the main application container.
4. Test after applying — tools relying on `ping`, packet capture, or raw socket libraries inside the container image will fail until re-implemented or explicitly re-granted the capability.
5. Enforce via Pod Security Admission `restricted` profile or an admission controller requiring `drop: ["ALL"]` as a baseline for all new workloads.

## References
- [Checkov check source (Kubernetes)](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/DropCapabilities.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/kubernetes/DropCapabilities.py)
- [Kubernetes: Configure a Security Context for a Pod or Container — Capabilities](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container)
