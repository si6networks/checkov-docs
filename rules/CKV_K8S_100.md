# CKV_K8S_100: Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate
## Severity
**CRITICAL** (score: 9.0/10)

An API server missing --tls-cert-file/--tls-private-key-file may serve the Kubernetes control-plane API without TLS, exposing all API traffic, including authentication tokens and secrets, to interception.

## Summary
This check ensures the Kubernetes API server (`kube-apiserver`) is started with both `--tls-cert-file` and `--tls-private-key-file` arguments set to non-empty values, enabling TLS for its serving endpoint.

## Applicability
Applies to Kubernetes manifests defining container specs for workload kinds (`CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`) — in practice this check is meaningful only for the static Pod manifest that runs `kube-apiserver` itself (typically `/etc/kubernetes/manifests/kube-apiserver.yaml` on control-plane nodes), since it specifically looks for the `kube-apiserver` command inside a container's `command` list.

## Why it matters
The Kubernetes API server is the single most sensitive component in a cluster — every kubectl request, controller action, and node kubelet interaction flows through it, and it holds the credentials/authority to read and mutate all cluster state including Secrets. If the API server is not configured with a TLS certificate and private key (`--tls-cert-file`/`--tls-private-key-file`), its HTTPS endpoint cannot present a valid server certificate for the configured `--tls-cert-file`, which can mean the server falls back to a self-signed/auto-generated certificate or, in edge/misconfigured deployments, expose the endpoint without proper transport encryption enforcement. Without a deliberately provisioned certificate and key, clients cannot cryptographically verify the identity of the API server they're connecting to, opening the door to man-in-the-middle interception of highly privileged traffic (bearer tokens, Secret contents, exec/attach sessions) between administrators/controllers and the control plane. This maps to CIS Kubernetes Benchmark control 1.2.29/1.2.30 (API server TLS configuration).

## How Checkov evaluates this
`ApiServerTlsCertAndKey` (a `BaseK8sContainerCheck`) inspects each container's `command` list:
- If the container's command is not `kube-apiserver` (i.e., `"kube-apiserver"` is not present in the `command` array), the check **PASSES** (not applicable — this isn't the API server container).
- If it is `kube-apiserver`, the check scans each command-line argument: it looks for an argument starting with `--tls-cert-file` where the `=`-delimited value is non-empty, and separately for `--tls-private-key-file` with a non-empty value.
- **PASS** only if both flags are present with non-empty values; **FAIL** if either is missing or has an empty value.

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
        - --advertise-address=10.0.0.1
        - --etcd-servers=https://127.0.0.1:2379
        # missing --tls-cert-file / --tls-private-key-file
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
        - --advertise-address=10.0.0.1
        - --etcd-servers=https://127.0.0.1:2379
        - --tls-cert-file=/etc/kubernetes/pki/apiserver.crt      # fix
        - --tls-private-key-file=/etc/kubernetes/pki/apiserver.key  # fix
```

## Remediation steps
1. On each control-plane node, edit the static Pod manifest for `kube-apiserver` (commonly `/etc/kubernetes/manifests/kube-apiserver.yaml`) to include `--tls-cert-file=<path>` and `--tls-private-key-file=<path>` pointing at a valid certificate/key pair.
2. If using `kubeadm`, this is normally configured automatically during cluster bootstrap (`/etc/kubernetes/pki/apiserver.crt` and `apiserver.key`) — verify these flags weren't accidentally stripped by custom automation or a hand-edited manifest.
3. Ensure the certificate covers the correct Subject Alternative Names (cluster service IP, API server's advertised address/hostname, and `kubernetes.default.svc` etc.) so clients can validate it correctly.
4. Restrict filesystem permissions on the private key file (owned by root, mode 600) since it is highly sensitive.
5. After editing a static Pod manifest, the kubelet will automatically restart the API server Pod — verify the API server comes back healthy (`kubectl get componentstatuses` / `kubectl get --raw='/healthz'`) before considering the change complete.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/ApiServerTlsCertAndKey.py)
- [Kubernetes docs: kube-apiserver options (--tls-cert-file)](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
