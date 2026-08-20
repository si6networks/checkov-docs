# CKV_K8S_107: Ensure that the --profiling argument is set to false
## Severity
**MEDIUM** (score: 5.0/10)

Leaving controller-manager profiling (pprof) enabled exposes internal runtime/debug data and a CPU-intensive endpoint that can aid reconnaissance or low-effort denial-of-service against a control-plane component.

## Summary
This check verifies that the `kube-controller-manager` component disables Go pprof profiling endpoints by setting `--profiling=false`.

## Applicability
**Checkov framework(s):** `kubernetes`

Kubernetes manifests defining a Pod-carrying workload whose container `command` invokes `kube-controller-manager` — applicable entity kinds are `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`. In practice it only meaningfully evaluates the static Pod manifest for the `kube-controller-manager` control-plane component.

## Why it matters
When profiling is enabled, `kube-controller-manager` exposes `/debug/pprof` HTTP endpoints that reveal detailed internal runtime information — goroutine stacks, memory heap dumps, CPU profiles, and potentially sensitive data about cluster state and internal operations. An attacker with network access to this endpoint (or an insider) can use it for reconnaissance and, in some cases, to degrade performance by triggering expensive profiling operations (a resource-exhaustion / DoS vector). This is a standard CIS Kubernetes Benchmark hardening recommendation: profiling should be disabled in production unless actively debugging.

## How Checkov evaluates this
The check (`KubeControllerManagerBlockProfiles`) inspects the container's `command` list:
- If `command` is absent, or does not include `kube-controller-manager`, the check **PASSES** (not applicable).
- If `kube-controller-manager` is present, it scans tokens in `command` for one starting with `--profiling`; the value after `=` is compared to the string `"false"`.
  - As soon as a `--profiling=false` token is found, it **PASSES**.
  - If the loop completes without finding a `--profiling` flag equal to `false` (flag missing entirely, or set to `true`), it **FAILS**.

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
    - --use-service-account-credentials=true
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
    - --use-service-account-credentials=true
    - --profiling=false
```

## Remediation steps
1. Locate the static Pod manifest for `kube-controller-manager` (typically `/etc/kubernetes/manifests/kube-controller-manager.yaml`).
2. Add `--profiling=false` to the container `command` array (the flag defaults to `true` if omitted, which is why an absent flag fails this check).
3. Save the manifest — kubelet restarts the static Pod automatically.
4. If you need profiling temporarily for a debugging session, re-enable it manually and revert immediately afterward rather than leaving it on in a checked-in manifest.
5. This check does not apply to fully managed control planes (EKS/GKE/AKS) where you cannot set controller-manager flags; skip the check for those manifests if Checkov flags infrastructure you don't control.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/KubeControllerManagerBlockProfiles.py)
- [Kubernetes kube-controller-manager reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/)
