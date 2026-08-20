# CKV_K8S_92: Ensure that the --audit-log-maxage argument is set to 30 or as appropriate
## Severity
**LOW** (score: 2.0/10)

An inadequate audit-log retention (max-age) window shortens the historical window available for incident investigation but does not by itself prevent detection of an active compromise.

## Summary
This check verifies that a self-managed `kube-apiserver` container retains audit log files for at least 30 days via `--audit-log-maxage=30` (or higher).

## Applicability
**Checkov framework(s):** `kubernetes`

Kubernetes manifests only. Applies to pod-spec-bearing resources: `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`. Relevant only to the container spec of a self-hosted `kube-apiserver` static pod/manifest, and only meaningful when audit logging is enabled (see CKV_K8S_91).

## Why it matters
Audit logs are the primary forensic record for investigating security incidents involving the Kubernetes control plane. If old audit log files are deleted too aggressively (a short retention window), evidence of a breach discovered weeks after the fact — a common real-world detection lag — may already be gone, preventing effective incident response, root-cause analysis, or compliance reporting (many regulatory frameworks require 30+ days of retained security logs). Setting `--audit-log-maxage` too low silently degrades your security visibility without any obvious operational symptom until the day you actually need the logs and they aren't there.

## How Checkov evaluates this
The check (`ApiServerAuditLogMaxAge`, a `BaseK8sContainerCheck`) inspects the container's `command` list:
1. If `command` is `None` or doesn't contain `kube-apiserver`, returns PASSED.
2. If `kube-apiserver` is present, it looks for an argument starting with `--audit-log-maxage`, splits on `=` to extract the numeric value, and checks whether `int(value) >= 30`.
3. Returns PASSED only if such an argument is found and its value is >= 30; FAILED if the flag is absent or set below 30. Note: a malformed value that fails `int()` conversion would raise an exception rather than gracefully failing.

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
        - --audit-log-maxage=7
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
        - --audit-log-maxage=30
```

## Remediation steps
1. Set `--audit-log-maxage=30` (or a higher value matching your organization's log-retention policy) on the `kube-apiserver` command in the static pod manifest.
2. Confirm `--audit-log-path` is also set (see CKV_K8S_91) — `maxage` has no effect without audit logging enabled.
3. Ensure sufficient local disk space on the control-plane node for 30+ days of retained logs, or better, forward audit logs to centralized/remote storage (e.g., via a log-shipping sidecar or node-level agent) so local retention settings are a safety net rather than the sole retention mechanism.
4. Coordinate this value with any compliance requirements (PCI-DSS, SOC 2, HIPAA, etc.) your organization must meet — 30 days may be a minimum, not a target.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/ApiServerAuditLogMaxAge.py)
- [Kubernetes auditing documentation](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
