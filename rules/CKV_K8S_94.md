# CKV_K8S_94: Ensure that the --audit-log-maxsize argument is set to 100 or as appropriate
## Severity
**LOW** (score: 2.0/10)

An undersized audit-log max file size can cause log rotation/loss under high event volume, degrading the completeness of security audit trails without directly enabling exploitation.

## Summary
This check verifies that a self-managed `kube-apiserver` container rotates audit log files once they reach at least 100 MB via `--audit-log-maxsize=100` (or higher).

## Applicability
**Checkov framework(s):** `kubernetes`

Kubernetes manifests only. Applies to pod-spec-bearing resources: `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`. Relevant only to the container spec of a self-hosted `kube-apiserver` static pod/manifest, and only meaningful when audit logging is enabled (see CKV_K8S_91).

## Why it matters
`--audit-log-maxsize` sets the size threshold (in megabytes) at which the current audit log file is rotated. If set too small, the API server rotates logs excessively frequently on a busy cluster, which can defeat retention safeguards controlled by `--audit-log-maxbackup` (files get purged faster in wall-clock time even with a fixed backup count) and adds unnecessary I/O overhead from constant file rotation. Conversely, having no size cap at all risks a single unbounded log file consuming all available disk space on the control-plane node, which can crash or degrade the API server itself (disk-pressure eviction, `kube-apiserver` failing to write further audit entries, or the node becoming unresponsive) — turning an availability-hardening control into an availability risk if misconfigured.

## How Checkov evaluates this
The check (`ApiServerAuditLogMaxSize`, a `BaseK8sContainerCheck`) inspects the container's `command` list:
1. If `command` is `None` or doesn't contain `kube-apiserver`, returns PASSED.
2. If `kube-apiserver` is present, it looks for an argument starting with `--audit-log-maxsize`, splits on `=` to extract the value, and checks `int(value) >= 100`.
3. Returns PASSED only if the flag is present with a value >= 100; FAILED if absent or below 100.

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
        - --audit-log-path=/var/log/kubernetes/audit/audit.log
        - --audit-log-maxsize=20
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
        - --audit-log-path=/var/log/kubernetes/audit/audit.log
        - --audit-log-maxsize=100
        - --audit-log-maxbackup=10
        - --audit-log-maxage=30
```

## Remediation steps
1. Set `--audit-log-maxsize=100` (or higher, in MB) on the `kube-apiserver` command in the static pod manifest.
2. Size this relative to `--audit-log-maxbackup` and expected control-plane node disk capacity: total worst-case disk usage is roughly `maxsize x (maxbackup + 1)` MB, so plan disk allocation accordingly (e.g., 100 MB x 11 files ≈ 1.1 GB).
3. Monitor control-plane node disk utilization after changing this to avoid disk-pressure conditions.
4. Combine with `--audit-log-maxage` and `--audit-log-maxbackup` (CKV_K8S_92/93) — all three must be tuned together for a coherent, disk-safe retention policy.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/ApiServerAuditLogMaxSize.py)
- [Kubernetes auditing documentation](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
