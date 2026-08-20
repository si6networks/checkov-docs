# CKV_K8S_90: Ensure that the --profiling argument is set to false
## Severity
**LOW** (score: 2.0/10)

Leaving profiling enabled exposes detailed runtime performance/debug data via pprof endpoints that can aid an attacker in reconnaissance or resource-exhaustion attacks, but does not by itself grant access or control.

## Summary
This check verifies that a self-managed `kube-apiserver` container explicitly disables Go's runtime profiling endpoints via `--profiling=false`.

## Applicability
**Checkov framework(s):** `kubernetes`

Kubernetes manifests only. Applies to pod-spec-bearing resources: `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`. Relevant only to the container spec of a self-hosted `kube-apiserver` static pod/manifest.

## Why it matters
When profiling is enabled (the historical default, `--profiling=true`), the API server exposes `pprof` endpoints (`/debug/pprof/*`) that reveal detailed internal runtime information — goroutine stacks, memory allocation patterns, CPU profiles, and potentially sensitive data embedded in memory or stack traces. These endpoints also consume additional CPU/memory resources and expand the API server's attack surface: an attacker with network access to these endpoints can use them for reconnaissance (understanding internal request patterns, timing side-channels) or to trigger resource-intensive profiling operations as a denial-of-service vector. Disabling profiling in production is a standard CIS Kubernetes Benchmark hardening recommendation, since profiling data is intended only for debugging by cluster operators, not for production exposure.

## How Checkov evaluates this
The check (`ApiServerProfiling`, a `BaseK8sContainerCheck`) inspects the container's `command` list:
1. If `command` is `None`, or doesn't contain `kube-apiserver`, returns PASSED.
2. If `kube-apiserver` is present, it FAILS unless the exact literal string `--profiling=false` appears in the command list — any other value, a differently-formatted argument (e.g. `--profiling false` as two separate list items), or complete absence of the flag causes FAILED.

## Non-compliant example
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
  namespace: kube-system
spec:
  containers:
    - name: kube-apiserver
      image: registry.k8s.io/kube-apiserver:v1.29.0
      command:
        - kube-apiserver
        - --etcd-servers=https://127.0.0.1:2379
        # --profiling not set; defaults to true
```

## Remediated example
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
  namespace: kube-system
spec:
  containers:
    - name: kube-apiserver
      image: registry.k8s.io/kube-apiserver:v1.29.0
      command:
        - kube-apiserver
        - --etcd-servers=https://127.0.0.1:2379
        - --profiling=false
```

## Remediation steps
1. Add `--profiling=false` to the `kube-apiserver` command/args in the static pod manifest (typically `/etc/kubernetes/manifests/kube-apiserver.yaml`).
2. Use the exact `--profiling=false` syntax (single token, `=`-joined) — the check does not recognize a two-token `--profiling false` form as compliant, and neither does the underlying flag parser reliably in all versions, so keep the `=` form for both correctness and compliance.
3. If you need profiling data temporarily for debugging a performance issue, re-enable it (`--profiling=true`) only on a non-production/test control plane, and revert immediately after collecting the data.
4. This same recommendation applies equally to `kube-controller-manager` and `kube-scheduler`, which expose the same `--profiling` flag — review and harden those too even though this specific check only targets `kube-apiserver`.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/ApiServerProfiling.py)
- [Kubernetes API server options reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)
