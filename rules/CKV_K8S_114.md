# CKV_K8S_114: Ensure that the --profiling argument is set to false
## Severity
**LOW** (score: 2.0/10)

Leaving scheduler profiling (pprof) enabled exposes internal runtime/debug data and a CPU-intensive endpoint that can aid reconnaissance or low-effort denial-of-service against a control-plane component.

## Summary
This check verifies that the `kube-scheduler` component disables Go pprof profiling by setting `--profiling=false`.

## Applicability
**Checkov framework(s):** `kubernetes`

Kubernetes manifests defining a Pod-carrying workload whose container `command` invokes `kube-scheduler` — applicable entity kinds are `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`. In practice it only meaningfully evaluates the static Pod manifest for the `kube-scheduler` control-plane component.

## Why it matters
When profiling is enabled, `kube-scheduler` exposes `/debug/pprof` HTTP endpoints revealing internal runtime data — goroutine dumps, memory profiles, and CPU profiles that can leak details about scheduling decisions and internal state. This is unnecessary attack surface and a potential resource-exhaustion vector (triggering profiling operations is CPU/memory intensive) on a component that is on the critical path for placing every Pod in the cluster. Disabling profiling in production, per CIS Kubernetes Benchmark guidance, removes this debug surface while leaving it available to re-enable temporarily for genuine troubleshooting.

## How Checkov evaluates this
The check (`SchedulerProfiling`) inspects the container's `command` list:
- If `command` is absent, or does not include `kube-scheduler`, the check **PASSES** (not applicable).
- If `kube-scheduler` is present, it checks whether the literal string `--profiling=false` appears anywhere in the `command` list.
  - If present, the check **PASSES**.
  - If absent (flag missing, entirely, or written differently e.g. `--profiling=true`), the check **FAILS**.
- Note this is a stricter, exact-string match (unlike CKV_K8S_107's controller-manager equivalent, which parses on `=` and compares the value) — `--profiling =false` or unusual spacing would not match.

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
    - --bind-address=127.0.0.1
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
    - --profiling=false
```

## Remediation steps
1. Locate the static Pod manifest for `kube-scheduler` (typically `/etc/kubernetes/manifests/kube-scheduler.yaml`).
2. Add `--profiling=false` as its own exact entry in the container `command` array.
3. Save the manifest — the static Pod restarts automatically to pick up the change.
4. Re-enable profiling only temporarily and manually for active debugging sessions, then revert.
5. Not applicable to fully managed control planes (EKS/GKE/AKS) where you cannot configure `kube-scheduler` flags directly.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/SchedulerProfiling.py)
- [Kubernetes kube-scheduler reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-scheduler/)
