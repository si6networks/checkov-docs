# CKV_K8S_112: Ensure that the RotateKubeletServerCertificate argument is set to true
## Severity
**MEDIUM** (score: 5.0/10)

Disabling automatic kubelet server certificate rotation leaves long-lived certificates in place, increasing exposure if a certificate or its key is ever compromised, though it does not by itself create an active exploit path.

## Summary
This check verifies that neither `kube-controller-manager` nor `kubelet` explicitly disables the `RotateKubeletServerCertificate` feature gate, which governs automatic rotation of the kubelet's server (serving) TLS certificate.

## Applicability
Kubernetes manifests defining a Pod-carrying workload whose container `command` invokes `kube-controller-manager` or `kubelet` — applicable entity kinds are `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`. In practice it evaluates the static Pod manifests for the `kube-controller-manager` control-plane component and any manifest that surfaces kubelet's command-line flags (e.g. via a kubelet config rendered as a Pod command, per CIS-1.6 4.2.12).

## Why it matters
The kubelet's serving certificate is what it presents to clients (the API server, `kubectl exec`/`logs`/`port-forward` proxies) connecting to its HTTPS endpoint. Without automatic rotation (`RotateKubeletServerCertificate=true`, the default since it graduated to stable), operators must manually reissue and redistribute kubelet serving certs before they expire — a task that is frequently missed at scale. An expired kubelet serving certificate causes the API server to be unable to reach that node for exec/logs/metrics, degrading operational visibility and troubleshooting ability, and forces emergency manual cert reissuance. Explicitly disabling rotation (`RotateKubeletServerCertificate=false`) removes an important automated hygiene control this CIS Kubernetes Benchmark (4.2.12) item is designed to keep on.

## How Checkov evaluates this
The check (`RotateKubeletServerCertificate`) looks at the container's `command` list:
- It only evaluates commands that include either `kube-controller-manager` or `kubelet` (defined as `COMPONENT_TYPES`).
- For each token in `command`, if a token starts with `--feature-gates` and contains the literal substring `RotateKubeletServerCertificate=false`, the check **FAILS** immediately.
- If no such token is found (feature gate not explicitly disabled — including when it's entirely absent, since the flag defaults to enabled), the check **PASSES**.
- This means the check is only tripped by an explicit opt-out; it does not require the flag to be explicitly set to `true`.

## Non-compliant example
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kube-controller-manager
  namespace: kube-system
spec:
  containers:
  - name: kube-controller-manager
    image: k8s.gcr.io/kube-controller-manager:v1.28.0
    command:
    - kube-controller-manager
    - --feature-gates=RotateKubeletServerCertificate=false
```

## Remediated example
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kube-controller-manager
  namespace: kube-system
spec:
  containers:
  - name: kube-controller-manager
    image: k8s.gcr.io/kube-controller-manager:v1.28.0
    command:
    - kube-controller-manager
    - --feature-gates=RotateKubeletServerCertificate=true
```

## Remediation steps
1. Search your static Pod manifests / kubelet config for any `--feature-gates` argument that disables `RotateKubeletServerCertificate`.
2. Remove the `RotateKubeletServerCertificate=false` entry (or flip it to `true`) so kubelet's server certificate auto-rotates before expiry.
3. Ensure the `certificates.k8s.io/v1` CSR approval flow is functioning (an approving controller such as kube-controller-manager's built-in CSR approver, or a custom approver) — rotation depends on CSRs being approved automatically.
4. Restart the affected component (static Pods restart automatically on manifest change; kubelet requires a service restart if configured via `/var/lib/kubelet/config.yaml`).
5. Verify with `kubectl get csr` that new kubelet-serving CSRs are being approved and certificates renewed over time.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/RotateKubeletServerCertificate.py)
- [Kubernetes: Kubelet configuration / TLS bootstrapping](https://kubernetes.io/docs/reference/access-authn-authz/kubelet-tls-bootstrapping/)
