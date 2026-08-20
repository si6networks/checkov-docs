# CKV_K8S_33: Ensure the Kubernetes dashboard is not deployed

## Severity
**LOW** (score: 2.0/10)

The Kubernetes Dashboard has repeatedly been abused as a cluster-takeover vector (e.g. the 2018 Tesla incident) because it is frequently deployed with excessive default RBAC and weak/no authentication, so its mere presence materially raises the risk of full cluster compromise.

## Summary
This check flags workloads that deploy the Kubernetes Dashboard container image or carry its characteristic labels, since the Dashboard has historically been a common cluster-compromise vector.

## Applicability
Kubernetes manifests only, evaluated at the container level across kinds: `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`.

## Why it matters
The Kubernetes Dashboard has a well-documented history of being deployed with overly permissive service account bindings (in older default installs, `cluster-admin`) and exposed without authentication, making it one of the most common ways attackers who gain any network access to a cluster escalate to full cluster compromise — a pattern seen in numerous real-world cryptojacking and cluster-takeover incidents. Even when hardened, the Dashboard is a large, complex, frequently-targeted web application that increases the attack surface unnecessarily for clusters that don't strictly require a browser UI. Checkov flags its presence so that teams consciously decide to run it (with proper RBAC scoping, authentication, and network restriction) rather than deploying it as an incidental default.

## How Checkov evaluates this
For each container, the check inspects the `image` field: if it's a string containing `kubernetes-dashboard` or `kubernetesui` (the official image registry/repo names), the check FAILS. It also inspects the enclosing resource's `metadata.labels`: if `labels.app == "kubernetes-dashboard"` or `labels["k8s-app"] == "kubernetes-dashboard"`, it FAILS. Otherwise it PASSES.

## Non-compliant example
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kubernetes-dashboard
  labels:
    k8s-app: kubernetes-dashboard
spec:
  replicas: 1
  selector:
    matchLabels:
      k8s-app: kubernetes-dashboard
  template:
    metadata:
      labels:
        k8s-app: kubernetes-dashboard
    spec:
      containers:
        - name: kubernetes-dashboard
          image: kubernetesui/dashboard:v2.7.0
```

## Remediated example
```yaml
# Do not deploy the Kubernetes Dashboard.
# Use kubectl proxy + `kubectl port-forward`, or a properly access-controlled
# observability tool (e.g. Lens, k9s locally, or a vetted internal UI)
# scoped with least-privilege RBAC and behind SSO/mTLS if a UI is required.
```

## Remediation steps
1. Remove the Dashboard Deployment/manifest entirely if it isn't a hard requirement.
2. If a web UI for cluster inspection is genuinely needed, deploy the Dashboard only in a tightly network-restricted namespace, bind it to a ServiceAccount with least-privilege RBAC (never `cluster-admin`), require token/OIDC login, and never expose it via a public LoadBalancer/Ingress.
3. Prefer `kubectl proxy` with local port-forwarding for ad-hoc access instead of a persistent, network-reachable Dashboard.
4. If the check is a false positive (e.g. an unrelated app happens to use the `k8s-app` label with a different value), verify the label/image aren't actually the Dashboard before suppressing.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/KubernetesDashboard.py)
- [Kubernetes docs: Web UI (Dashboard)](https://kubernetes.io/docs/tasks/access-application-cluster/web-ui-dashboard/)
