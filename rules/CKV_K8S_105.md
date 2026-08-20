# CKV_K8S_105: Ensure that the API Server only makes use of Strong Cryptographic Ciphers
## Severity
**HIGH** (score: 7.5/10)

Permitting weak or non-forward-secret cipher suites on the API server's TLS listener weakens control-plane transport security against downgrade and cryptanalytic attacks.

## Summary
This check ensures that if the Kubernetes API server's `--tls-cipher-suites` argument is set, every cipher suite listed is drawn from an approved set of strong, modern TLS cipher suites.

## Applicability
Applies to Kubernetes manifests defining container specs for workload kinds (`CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`) — relevant specifically to the static Pod manifest running `kube-apiserver`, since the check looks for the `kube-apiserver` command.

## Why it matters
The API server's TLS cipher suite configuration determines which cryptographic algorithms are permitted for the encrypted channel that all cluster administration, kubelet, and controller traffic flows over. Weak or legacy cipher suites (e.g., those relying on RC4, 3DES, static RSA key exchange without forward secrecy, or CBC-mode ciphers combined with older TLS versions vulnerable to padding-oracle attacks such as Lucky13/BEAST/POODLE-adjacent issues) can allow an attacker positioned on the network path to more feasibly downgrade, decrypt, or tamper with API server traffic — potentially exposing bearer tokens, Secret contents transmitted over the API, or exec/attach session data. Restricting the API server to only modern AEAD ciphers with forward secrecy (ECDHE key exchange + AES-GCM/ChaCha20-Poly1305) closes off downgrade and cryptanalytic attack paths against the most privileged channel in the cluster. This corresponds to CIS Kubernetes Benchmark control 1.2.35.

## How Checkov evaluates this
`ApiServerStrongCryptographicCiphers` (a `BaseK8sContainerCheck`) inspects the container's `command` list:
- If `kube-apiserver` is not in the command, the check **PASSES** (not the API server container).
- If it is, the check scans for an argument starting with `--tls-cipher-suites`. If found, it splits the `=`-delimited value on commas to get the list of configured cipher suite names, then checks each one against a hardcoded allow-list:
  ```
  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305
  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
  TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305
  TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
  TLS_RSA_WITH_AES_256_GCM_SHA384
  TLS_RSA_WITH_AES_128_GCM_SHA256
  ```
- **FAIL** as soon as any listed cipher is not in this allow-list.
- If `--tls-cipher-suites` is not set at all, the check **PASSES** — Checkov does not flag the absence of the flag, only the presence of a weak cipher when the flag IS set (i.e., this check validates an explicit configuration, it doesn't mandate that one exists).

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
        - --tls-cipher-suites=TLS_RSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        # TLS_RSA_WITH_3DES_EDE_CBC_SHA is a weak/legacy cipher not in the allow-list
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
        - --tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305   # fix: only strong AEAD/forward-secret ciphers
```

## Remediation steps
1. Edit the `kube-apiserver` static Pod manifest and set `--tls-cipher-suites` to a comma-separated list containing only ciphers from the strong allow-list above (prefer the ECDHE + AES-GCM/ChaCha20-Poly1305 entries, which provide forward secrecy; the two `TLS_RSA_*` entries lack forward secrecy and should be avoided if client compatibility permits).
2. Remove any RC4, 3DES, CBC-with-SHA1, static-RSA key-exchange, or export-grade ciphers from the list.
3. Verify client compatibility (kubelets, controllers, kubectl, any custom API clients) supports at least one of the retained cipher suites before rolling this out cluster-wide — an overly restrictive list can break connectivity for older Go-based clients.
4. If you don't set `--tls-cipher-suites` at all, Go's/Kubernetes' built-in default cipher suite set is used, which is reasonably modern but less explicit; consider setting it explicitly for auditability even though Checkov won't flag its absence.
5. After changing the static manifest, the kubelet restarts the API server automatically — verify cluster connectivity and control-plane health afterward.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/ApiServerStrongCryptographicCiphers.py)
- [Kubernetes docs: kube-apiserver options (--tls-cipher-suites)](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
