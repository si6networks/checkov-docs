# CKV_K8S_113: Ensure that the --bind-address argument is set to 127.0.0.1
## Severity
**HIGH** (score: 7.5/10)

Binding the controller-manager to an address other than 127.0.0.1 exposes its unauthenticated HTTP endpoints (health/metrics) to the network, giving remote attackers reconnaissance and potential denial-of-service access to a core control-plane process.

## Summary
This check verifies that `kube-controller-manager` binds its (unauthenticated, non-HTTPS-secured legacy) HTTP endpoint to the loopback address `127.0.0.1` rather than a routable/external interface.

## Applicability
Kubernetes manifests defining a Pod-carrying workload whose container `command` invokes `kube-controller-manager` — applicable entity kinds are `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`. In practice it only meaningfully evaluates the static Pod manifest for the `kube-controller-manager` control-plane component.

## Why it matters
`kube-controller-manager`'s legacy HTTP endpoint (historically served on port 10252) has no built-in authentication or authorization. If `--bind-address` is set to `0.0.0.0` or another externally-reachable address, that endpoint — which exposes health, metrics, and debug data about the controller manager — becomes reachable from the network. Depending on network segmentation, that can leak internal cluster operational details to anyone who can route to the control-plane node, or serve as a reconnaissance/DoS target. Restricting the bind address to loopback (`127.0.0.1`) ensures the endpoint is only reachable from processes on the same host (e.g. a local metrics scraper going through a secured proxy), consistent with CIS Kubernetes Benchmark control-plane hardening guidance.

## How Checkov evaluates this
The check (`ControllerManagerBindAddress`) inspects the container's `command` list:
- If `command` is absent, or does not include `kube-controller-manager`, the check **PASSES** (not applicable).
- If `kube-controller-manager` is present, it scans each token containing `=`, splitting into `key`/`value`.
  - As soon as it finds `key == "--bind-address"` and `value == "127.0.0.1"`, it **PASSES**.
  - If the loop completes without finding that exact key/value pair (flag missing, or set to any other address such as `0.0.0.0`), it **FAILS**.

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
    - --bind-address=0.0.0.0
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
    - --bind-address=127.0.0.1
```

## Remediation steps
1. Locate the static Pod manifest for `kube-controller-manager` (typically `/etc/kubernetes/manifests/kube-controller-manager.yaml`).
2. Set `--bind-address=127.0.0.1` explicitly in the container `command` array.
3. If external metrics scraping (e.g. Prometheus) needs access to controller-manager metrics, route through a locally-running authenticated proxy (such as `kube-rbac-proxy`) rather than widening the bind address.
4. Save the manifest — the static Pod restarts automatically to apply the change.
5. Confirm with `ss -tlnp` (or `netstat`) on the control-plane node that the controller-manager port is only listening on `127.0.0.1`, not `0.0.0.0`.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/ControllerManagerBindAddress.py)
- [Kubernetes kube-controller-manager reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/)
