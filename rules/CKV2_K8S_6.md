# CKV2_K8S_6: Minimize the admission of pods which lack an associated NetworkPolicy

## Severity
**MEDIUM** (score: 5.0/10)

Pods admitted without an associated NetworkPolicy default to unrestricted pod-to-pod network access, weakening segmentation and easing lateral movement after a workload is compromised, but this alone does not directly expose data or credentials.

## Summary
This check ensures every `Pod` (including those created by a `Deployment`) has at least one `NetworkPolicy` selecting it, so that network traffic to/from the pod is explicitly governed rather than left fully open by default.

## Applicability
Kubernetes manifests. Applies to `Pod` and `Deployment` resource kinds (a Deployment's pod template is treated as the Pod for graph-connection purposes), checked against `NetworkPolicy` resources in the same namespace.

## Why it matters
By default, Kubernetes networking is fully permissive: any pod can send traffic to, and receive traffic from, any other pod in the cluster (and often ingress traffic from outside the cluster), unless a `NetworkPolicy` explicitly restricts it. This flat, trust-everything network model means that if any single pod is compromised (e.g. via a vulnerable dependency or RCE), the attacker can immediately reach every other service in the cluster — databases, internal APIs, metadata services — with no additional lateral-movement effort. Enforcing that every pod has an associated NetworkPolicy is a foundational "least privilege networking" control (also called for in the CIS Kubernetes Benchmark and NSA/CISA Kubernetes Hardening Guide): it ensures ingress/egress traffic for each workload is deliberately scoped, so a compromised pod's blast radius is contained to only the connections it was explicitly granted.

## How Checkov evaluates this
Graph-based JSON policy (`RequireAllPodsToHaveNetworkPolicy.json`). It:
1. Filters resources to those of `resource_type` `Pod` (Deployments' generated pod objects included).
2. Requires a graph `connection` to `exist` between the `Pod`/`Deployment` and a `NetworkPolicy` resource — meaning the NetworkPolicy's `podSelector` (namespace + labels) must match the pod.
3. Passes only if at least one NetworkPolicy resource in the same namespace selects the pod's labels; fails if no NetworkPolicy connection exists (i.e., the pod is unprotected by any explicit ingress/egress policy).

## Non-compliant example
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: otel-collector
  namespace: observability
spec:
  replicas: 1
  selector:
    matchLabels:
      app: otel-collector
  template:
    metadata:
      labels:
        app: otel-collector
    spec:
      containers:
      - name: otel-collector
        image: otel/opentelemetry-collector:0.96.0
        ports:
        - containerPort: 4317
# No NetworkPolicy anywhere in the manifest set selects app: otel-collector
```

## Remediated example
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: otel-collector
  namespace: observability
spec:
  replicas: 1
  selector:
    matchLabels:
      app: otel-collector
  template:
    metadata:
      labels:
        app: otel-collector
    spec:
      containers:
      - name: otel-collector
        image: otel/opentelemetry-collector:0.96.0
        ports:
        - containerPort: 4317
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: otel-collector-netpol
  namespace: observability
spec:
  podSelector:
    matchLabels:
      app: otel-collector          # explicitly binds this policy to the Deployment's pods
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: observability
    ports:
    - protocol: TCP
      port: 4317
  egress:
  - to:
    - namespaceSelector: {}
    ports:
    - protocol: TCP
      port: 443
```

## Remediation steps
1. For every Deployment/Pod flagged, author a `NetworkPolicy` in the same namespace whose `podSelector.matchLabels` matches the workload's pod labels exactly.
2. Define explicit `ingress` rules allowing only the specific namespaces/pods/ports that legitimately need to reach this workload (e.g. only the app namespace can send telemetry to the collector on port 4317).
3. Define explicit `egress` rules allowing only the destinations the workload needs (e.g. DNS on port 53, an upstream backend on 443) — avoid `egress: [{}]` (allow-all) unless truly required.
4. Verify the cluster's CNI plugin actually enforces `NetworkPolicy` (e.g. Calico, Cilium, or Azure CNI with policy enabled) — policies are silently no-ops on CNIs that don't support them (e.g. plain flannel).
5. Where many workloads in a namespace should default to "deny all unless explicitly allowed," add a namespace-wide default-deny NetworkPolicy (`podSelector: {}` with no ingress/egress rules) as a baseline, then layer specific allow policies per workload.
6. Re-scan with Checkov after adding policies to confirm each Deployment/Pod now resolves a connection to a NetworkPolicy.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/graph_checks/RequireAllPodsToHaveNetworkPolicy.json
- Kubernetes NetworkPolicy docs: https://kubernetes.io/docs/concepts/services-networking/network-policies/
