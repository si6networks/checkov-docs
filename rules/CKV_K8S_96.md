# CKV_K8S_96: Ensure that the --service-account-lookup argument is set to true
## Severity
**HIGH** (score: 7.5/10)

Disabling service-account token lookup prevents the API server from validating tokens against live, non-deleted ServiceAccount objects, so revoked or deleted service account tokens can still be used to authenticate to the cluster.

## Summary
This check verifies that a self-managed `kube-apiserver` container explicitly enables live ServiceAccount validation via `--service-account-lookup=true`.

## Applicability
**Checkov framework(s):** `kubernetes`

Kubernetes manifests only. Applies to pod-spec-bearing resources: `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`. Relevant only to the container spec of a self-hosted `kube-apiserver` static pod/manifest.

## Why it matters
When `--service-account-lookup` is true, the API server validates every ServiceAccount token against the live `ServiceAccount` object in the API — meaning if the ServiceAccount is deleted (or its token is manually revoked), any tokens minted for it are immediately invalidated, even if the JWT itself hasn't expired. If this is disabled (`false`), a ServiceAccount token remains valid purely based on its own signature and expiry, regardless of whether the underlying ServiceAccount still exists — so deleting a compromised or offboarded ServiceAccount does not revoke tokens already issued to it. This significantly weakens incident response: an operator's attempt to "revoke access" by deleting a ServiceAccount would silently fail to invalidate any tokens an attacker had already exfiltrated.

## How Checkov evaluates this
The check (`ApiServerServiceAccountLookup`, a `BaseK8sContainerCheck`) inspects the container's `command` list:
1. If `command` is `None` or doesn't contain `kube-apiserver`, returns PASSED.
2. If `kube-apiserver` is present, it FAILS if either:
   - `--service-account-lookup=false` is present in the command list, OR
   - `--service-account-lookup=true` is **not** present in the command list.
3. In effect, the check only passes when the exact literal `--service-account-lookup=true` string appears — omitting the flag entirely (even though the Kubernetes default for this flag is `true`) is treated as FAILED by this check's logic, since the second condition (`not in command`) triggers.

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
        # --service-account-lookup not set (Checkov treats this as FAILED)
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
        - --service-account-lookup=true
```

## Remediation steps
1. Explicitly add `--service-account-lookup=true` to the `kube-apiserver` command/args, even though it matches the Kubernetes upstream default — Checkov's check requires the flag to be explicitly present.
2. Confirm it is not simultaneously set to `false` anywhere else in the argument list (some templates may have leftover conflicting flags from copy-pasted configs).
3. Verify the change doesn't break any workflow that depends on tokens outliving their ServiceAccount object (this should generally not be relied upon, as it is itself a security anti-pattern).
4. After the change, test that deleting a ServiceAccount does in fact invalidate tokens minted for it: create a test ServiceAccount, obtain a token, delete the ServiceAccount, and confirm the token is rejected by the API server.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/ApiServerServiceAccountLookup.py)
- [Kubernetes API server options reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)
