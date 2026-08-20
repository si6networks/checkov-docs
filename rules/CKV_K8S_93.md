# CKV_K8S_93: Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate
## Severity
**LOW** (score: 2.0/10)

An insufficient audit-log backup count risks premature loss of historical audit records, weakening long-term forensic capability without directly enabling an attack.

## Summary
This check verifies that a self-managed `kube-apiserver` container retains at least 10 rotated audit log backup files via `--audit-log-maxbackup=10` (or higher).

## Applicability
Kubernetes manifests only. Applies to pod-spec-bearing resources: `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`. Relevant only to the container spec of a self-hosted `kube-apiserver` static pod/manifest, and only meaningful when audit logging is enabled (see CKV_K8S_91).

## Why it matters
`--audit-log-maxbackup` controls how many rotated (aged-out) audit log files are retained on disk before the oldest is deleted. If this value is too low, rotated logs are purged quickly regardless of the `--audit-log-maxage` setting — under high API request volume, log files can rotate (due to size limits) many times per day, so a low backup count can silently defeat a well-intentioned `maxage` setting by deleting files well before they reach 30 days old. This creates gaps in the audit trail that undermine incident investigation and compliance evidence, exactly the scenario `maxage` was meant to prevent.

## How Checkov evaluates this
The check (`ApiServerAuditLogMaxBackup`, a `BaseK8sContainerCheck`) inspects the container's `command` list:
1. If `command` is `None` or doesn't contain `kube-apiserver`, returns PASSED.
2. If `kube-apiserver` is present, it looks for an argument starting with `--audit-log-maxbackup`, splits on `=` to extract the value, and checks `int(value) >= 10`.
3. Returns PASSED only if the flag is present and its value is >= 10; FAILED if absent or below 10.

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
        - --audit-log-maxbackup=2
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
        - --audit-log-maxbackup=10
        - --audit-log-maxage=30
        - --audit-log-maxsize=100
```

## Remediation steps
1. Set `--audit-log-maxbackup=10` (or higher, sized to your expected log rotation frequency and retention needs) on the `kube-apiserver` command.
2. Set this alongside `--audit-log-maxage` and `--audit-log-maxsize` together — these three flags jointly determine actual retention; a high `maxage` with a low `maxbackup` and high request volume can still purge logs early.
3. Monitor actual disk usage on the control-plane node after changing this, since retaining more backup files increases local storage consumption for the audit log directory.
4. Prefer forwarding audit logs to a centralized log store (ELK, Splunk, cloud logging) as the durable source of truth, treating local rotation settings as a bounded local buffer rather than the long-term archive.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/ApiServerAuditLogMaxBackup.py)
- [Kubernetes auditing documentation](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
