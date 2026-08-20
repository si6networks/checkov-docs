# CKV_K8S_91: Ensure that the --audit-log-path argument is set
## Severity
**MEDIUM** (score: 5.0/10)

Without an audit log path configured, security-relevant API server events are not recorded at all, eliminating the forensic and detection capability needed to identify malicious cluster activity.

## Summary
This check verifies that a self-managed `kube-apiserver` container has audit logging enabled by setting the `--audit-log-path` argument to a target log file.

## Applicability
**Checkov framework(s):** `kubernetes`

Kubernetes manifests only. Applies to pod-spec-bearing resources: `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`. Relevant only to the container spec of a self-hosted `kube-apiserver` static pod/manifest.

## Why it matters
Kubernetes audit logs record every request made to the API server — who made it, what resource was affected, what verb was used, and the response — providing the forensic trail needed to detect and investigate unauthorized access, privilege escalation, or data exfiltration. Without `--audit-log-path` set, the API server produces no persistent audit trail at all (audit logging is opt-in and disabled by default), meaning a security incident involving the control plane (e.g., a compromised service account being used to read Secrets, or a malicious `kubectl exec` into a sensitive pod) would leave no record for incident response or compliance audits. This is a baseline CIS Kubernetes Benchmark control.

## How Checkov evaluates this
The check (`ApiServerAuditLog`, a `BaseK8sContainerCheck`) inspects the container's `command` list:
1. If `command` is `None`, returns PASSED (not applicable).
2. If `kube-apiserver` is in the command list, it iterates every argument checking whether any starts with the prefix `--audit-log-path` (this matches both `--audit-log-path=/var/log/...` and any other suffix, as it's a `startswith` check, not an exact match).
3. Returns PASSED if any such argument was found, FAILED otherwise. Note it does not validate the file path value itself, only that the flag prefix is present.

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
        # no --audit-log-path set; no audit trail is produced
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
        - --audit-log-path=/var/log/kubernetes/audit/audit.log
        - --audit-policy-file=/etc/kubernetes/audit-policy.yaml
      volumeMounts:
        - name: audit-log
          mountPath: /var/log/kubernetes/audit
        - name: audit-policy
          mountPath: /etc/kubernetes/audit-policy.yaml
  volumes:
    - name: audit-log
      hostPath: { path: /var/log/kubernetes/audit, type: DirectoryOrCreate }
    - name: audit-policy
      hostPath: { path: /etc/kubernetes/audit-policy.yaml, type: File }
```

## Remediation steps
1. Add `--audit-log-path=<path>` to the `kube-apiserver` command, pointing at a writable, persistent path on the control-plane node.
2. Also define `--audit-policy-file` pointing to an audit policy manifest that specifies which request stages/verbs/resources to log (audit logging requires a policy file to actually emit entries — path alone with no policy produces no useful output on some setups, though the check itself only validates the path flag).
3. Mount both the audit policy file and the log output directory into the `kube-apiserver` static pod via `hostPath` volumes, since it runs as a static pod outside the normal scheduler.
4. Configure log rotation (`--audit-log-maxage`, `--audit-log-maxbackup`, `--audit-log-maxsize` — see CKV_K8S_92/93/94) so the audit log doesn't fill the control-plane node's disk.
5. Ship audit logs off-node to a SIEM or centralized logging system for durable retention and alerting, since the local log file alone is not resilient to node loss.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/ApiServerAuditLog.py)
- [Kubernetes auditing documentation](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
