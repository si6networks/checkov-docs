# CKV_K8S_69: Ensure that the --basic-auth-file argument is not set
## Severity
**LOW** (score: 2.0/10)

A configured basic-auth file stores API server credentials as long-lived cleartext passwords with no rotation or lockout, materially weakening authentication compared to token- or cert-based schemes.

## Summary
This check fails a `kube-apiserver` container manifest if its `command` includes a `--basic-auth-file` argument at all, since basic-auth-file support is a legacy, insecure authentication mechanism.

## Applicability
Kubernetes manifests where a container's `command` launches `kube-apiserver` — evaluated across `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet` (any workload kind containing a container), in practice firing only on control-plane static pod manifests or templates for `kube-apiserver`.

## Why it matters
`--basic-auth-file` configures HTTP Basic Authentication for the API server, backed by a static CSV file of `password,username,uid` entries. This mechanism has serious weaknesses: credentials are stored and transmitted (over TLS, but still) as unsalted static passwords, the file must be manually rotated (no built-in expiry/rotation), it doesn't support MFA, and any process able to read the file gets full plaintext credentials for any listed user. It was deprecated in Kubernetes and removed entirely in v1.19. Using it undermines defense-in-depth credential hygiene and is explicitly called out by CIS Kubernetes Benchmark 1.2.5. Removing it forces reliance on stronger auth (X.509 client certs, OIDC tokens, webhook token auth, or service account tokens).

## How Checkov evaluates this
`ApiServerBasicAuthFile.py`: if the container's `command` is a list and contains `"kube-apiserver"`, the check fails if **any** command token starts with `"--basic-auth-file"` (regardless of the value after `=`). If the flag is absent, or the container doesn't run `kube-apiserver`, it passes.

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
    - --basic-auth-file=/etc/kubernetes/basic_auth.csv   # legacy, weak auth -> FAILS
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
    # --basic-auth-file removed; strong auth (OIDC) used instead
```

## Remediation steps
1. Remove the `--basic-auth-file` flag entirely from the `kube-apiserver` command/manifest.
2. Migrate any users/automations relying on basic auth to a supported authentication strategy: X.509 client certificates, OIDC/OpenID Connect tokens, service account (bound) tokens, or a webhook token authenticator.
3. Rotate out and delete the basic-auth CSV file from disk once no longer referenced, since it contains plaintext credentials.
4. This flag is already removed in Kubernetes >= 1.19, so if your control plane is on a supported version, this should be a non-issue — treat any occurrence as a strong signal of an outdated/custom API server build.
5. Re-scan with `checkov -d . --check CKV_K8S_69`.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/ApiServerBasicAuthFile.py)
- [Kubernetes Authenticating documentation](https://kubernetes.io/docs/reference/access-authn-authz/authentication/)
