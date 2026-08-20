# CKV_K8S_70: Ensure that the --token-auth-file argument is not set
## Severity
**LOW** (score: 2.0/10)

A token-auth-file configures static, non-expiring bearer tokens for API server authentication, which if leaked provide durable unauthorized access with no built-in revocation/rotation mechanism.

## Summary
This check fails a `kube-apiserver` container manifest if its `command` includes any argument starting with `--token-auth-file`, since static token file authentication is a legacy, weak credential mechanism.

## Applicability
Kubernetes manifests where a container's `command` runs `kube-apiserver`, evaluated across container-bearing kinds (`CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`) — in practice, a self-managed/on-prem control-plane static pod manifest for `kube-apiserver`.

## Why it matters
`--token-auth-file` configures the API server to authenticate bearer tokens against a static CSV file (`token,username,uid,"group1,group2"`). Like `--basic-auth-file`, these are long-lived, unrotatable, unencrypted (at rest) static secrets: there is no expiry, no revocation short of editing the file and restarting the API server, and anyone who reads the file gets a valid credential for any listed identity indefinitely. This is CIS Kubernetes Benchmark 1.2.4. Static token files bypass modern auth features like short-lived tokens, OIDC claims-based identity, and audit-friendly credential lifecycles, making credential compromise both easier to achieve and harder to detect/contain.

## How Checkov evaluates this
`ApiServerTokenAuthFile.py`: if `command` is present and contains `"kube-apiserver"`, the check fails if any element of `command` starts with `"--token-auth-file"` (any value). Otherwise it passes.

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
    - --token-auth-file=/etc/kubernetes/tokens.csv   # static token auth -> FAILS
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
    - --oidc-issuer-url=https://accounts.example.com
    - --oidc-client-id=kubernetes
    # --token-auth-file removed; OIDC used instead
```

## Remediation steps
1. Remove `--token-auth-file` from the `kube-apiserver` command.
2. Migrate token-based clients to service account tokens (bound, time-limited, audience-scoped) issued via the `TokenRequest` API, or to OIDC-issued tokens for human users.
3. Securely delete the static token CSV file once no longer referenced.
4. Re-scan with `checkov -d . --check CKV_K8S_70` to confirm.
5. This is not applicable to managed Kubernetes offerings (EKS/GKE/AKS) where the control plane is provider-managed.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/ApiServerTokenAuthFile.py)
- [Kubernetes Authenticating documentation](https://kubernetes.io/docs/reference/access-authn-authz/authentication/)
