# CKV_K8S_19: Do not admit containers wishing to share the host network namespace
## Severity
**MEDIUM** (score: 5.0/10)

Sharing the host network namespace exposes the node's network interfaces and loopback services directly to the container, enabling traffic sniffing, spoofing, and bypass of network policy controls.

## Summary
This check fails any Pod/workload that sets `hostNetwork: true`, because that setting removes the container's isolated network namespace and exposes it directly on the node's network interfaces and loopback.

## Applicability
- **IaC framework:** Kubernetes manifests (YAML/JSON) and Terraform
- **Resource/entity types (Kubernetes):** `Pod`, `Deployment`, `DaemonSet`, `StatefulSet`, `ReplicaSet`, `ReplicationController`, `Job`, `CronJob`
- **Resource/entity types (Terraform):** `kubernetes_pod`, `kubernetes_pod_v1`, `kubernetes_deployment`, `kubernetes_deployment_v1`

## Why it matters
With `hostNetwork: true`, a Pod's containers share the node's network namespace directly instead of getting an isolated one connected via the CNI. This means the container can bind to any port on the host (including ports used by other pods or system daemons), sniff traffic on the node's loopback and physical interfaces, and reach any service listening on `localhost` on the node — including kubelet's read-only/read-write API ports, node-level metrics endpoints, or other locally-bound admin interfaces that were never meant to be network-exposed to workloads. It also breaks Kubernetes NetworkPolicy enforcement, since NetworkPolicies operate on the CNI-assigned pod network, not the host network. An attacker who compromises a `hostNetwork` pod effectively gets a foothold with the same network visibility as the node itself, which is a common stepping stone to broader cluster compromise. This is CIS Kubernetes Benchmark 1.7.4 / 5.2.4.

## How Checkov evaluates this
- **Kubernetes-native (`SharedHostNetworkNamespace`):** resolves the effective `spec` (directly for `Pod`, via `spec.jobTemplate.spec.template.spec` for `CronJob`, via `spec.template.spec` otherwise) and checks `hostNetwork`. Truthy → FAILED. Defaults to `false`, so absence PASSES.
- **Terraform (`SharedHostNetworkNamespace`, a `BaseResourceValueCheck`):** inspects `spec[0].host_network` (or nested under `template[0].spec[0]` for Deployments); expected value is `false`, and a missing block PASSES.

## Non-compliant example
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: fast-proxy
spec:
  hostNetwork: true
  containers:
    - name: proxy
      image: myorg/proxy:1.0
      ports:
        - containerPort: 8080
```

## Remediated example
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: fast-proxy
spec:
  hostNetwork: false
  containers:
    - name: proxy
      image: myorg/proxy:1.0
      ports:
        - containerPort: 8080
```

## Remediation steps
1. Remove `hostNetwork: true` (or set explicitly to `false`) unless there is a hard technical requirement, such as certain CNI plugins or node-level networking daemons that must genuinely operate on the host network.
2. If external connectivity is the actual goal, use a `Service` (ClusterIP/NodePort/LoadBalancer) or an Ingress controller instead of host networking.
3. If low-latency or DNS-related reasons were the motivation, consider `dnsPolicy: ClusterFirstWithHostNet` alternatives or a sidecar-based approach rather than granting full host network access.
4. Enforce this via Pod Security Admission (`baseline`/`restricted` disallows `hostNetwork`) or an admission controller so it is blocked outside a short, justified allowlist of infrastructure DaemonSets (e.g. CNI plugins) in dedicated namespaces.
5. Where `hostNetwork` is unavoidable (e.g. a CNI DaemonSet), compensate with tighter node-level firewalling and monitoring since NetworkPolicy will not apply to that pod.

## References
- [Checkov check source (Kubernetes)](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/SharedHostNetworkNamespace.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/kubernetes/SharedHostNetworkNamespace.py)
- [Kubernetes: Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
