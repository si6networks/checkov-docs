# CKV_K8S_115: Ensure that the --bind-address argument is set to 127.0.0.1
## Severity
**HIGH** (score: 7.5/10)

Binding the scheduler to an address other than 127.0.0.1 exposes its unauthenticated HTTP endpoints to the network, giving remote attackers reconnaissance and potential denial-of-service access to a core control-plane process.

## Summary
This check verifies that `kube-scheduler` binds its (unauthenticated legacy) HTTP endpoint to the loopback address `127.0.0.1` rather than a routable/external interface.

## Applicability
Kubernetes manifests defining a Pod-carrying workload whose container `command` invokes `kube-scheduler` — applicable entity kinds are `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`. In practice it only meaningfully evaluates the static Pod manifest for the `kube-scheduler` control-plane component.

## Why it matters
`kube-scheduler`'s legacy HTTP endpoint has no built-in authentication or authorization. If `--bind-address` is left at `0.0.0.0` (or any externally routable address) rather than restricted to loopback, that endpoint — exposing health/metrics/debug information about scheduling internals — becomes reachable from the network, expanding attack surface on a control-plane node. Anyone who can route to that port could gather reconnaissance data or attempt denial-of-service against a component that is on the critical path for placing every Pod cluster-wide. Restricting the bind address to `127.0.0.1` limits exposure to processes on the same host, per CIS Kubernetes Benchmark control-plane hardening guidance.

## How Checkov evaluates this
The check (`SchedulerBindAddress`) inspects the container's `command` list:
- If `command` is absent, or does not include `kube-scheduler`, the check **PASSES** (not applicable).
- If `kube-scheduler` is present, it scans each token containing `=`, splitting into `key`/`value`.
  - As soon as it finds `key == "--bind-address"` and `value == "127.0.0.1"`, it **PASSES**.
  - If the loop completes without a match (flag missing, or set to something other than `127.0.0.1`), it **FAILS**.

## Non-compliant example
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kube-scheduler
  namespace: kube-system
spec:
  containers:
  - name: kube-scheduler
    image: k8s.gcr.io/kube-scheduler:v1.28.0
    command:
    - kube-scheduler
    - --bind-address=0.0.0.0
```

## Remediated example
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kube-scheduler
  namespace: kube-system
spec:
  containers:
  - name: kube-scheduler
    image: k8s.gcr.io/kube-scheduler:v1.28.0
    command:
    - kube-scheduler
    - --bind-address=127.0.0.1
```

## Remediation steps
1. Locate the static Pod manifest for `kube-scheduler` (typically `/etc/kubernetes/manifests/kube-scheduler.yaml`).
2. Set `--bind-address=127.0.0.1` explicitly in the container `command` array.
3. If external metrics scraping needs access, route through a locally-running authenticated proxy (e.g. `kube-rbac-proxy`) instead of widening the bind address.
4. Save the manifest — the static Pod restarts automatically.
5. Verify with `ss -tlnp` on the control-plane node that the scheduler's port only listens on `127.0.0.1`.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/SchedulerBindAddress.py)
- [Kubernetes kube-scheduler reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-scheduler/)
