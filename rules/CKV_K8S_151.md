# CKV_K8S_151: Ensure that the Kubelet only makes use of Strong Cryptographic Ciphers
## Severity
**LOW** (score: 2.0/10)

Allowing weak TLS cipher suites on the kubelet API lets an attacker on the network path potentially downgrade or break the encryption protecting node management traffic, exposing credentials or command data.

## Summary
This check ensures that if the kubelet's `--tls-cipher-suites` argument is set, every listed cipher suite is from an approved list of strong, modern TLS ciphers.

## Applicability
**Checkov framework(s):** `kubernetes`

Kubernetes manifests for workload kinds carrying a pod template: `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`. It inspects the container `command` array, acting when it invokes `kubelet`.

## Why it matters
The kubelet's HTTPS API can be configured to use a restricted set of TLS cipher suites via `--tls-cipher-suites`. If weak, legacy, or non-forward-secret ciphers are included (e.g., ciphers using RC4, 3DES, static RSA key exchange, or CBC-mode ciphers vulnerable to padding-oracle style attacks), connections to the kubelet become susceptible to known cryptographic attacks (e.g., BEAST, POODLE-style issues, or simply weaker effective security allowing more feasible brute-force/downgrade attacks) and lack forward secrecy, meaning captured traffic could later be decrypted if the private key is ever compromised. Restricting to strong, AEAD, forward-secret ciphers (ECDHE + AES-GCM or ChaCha20-Poly1305) closes this class of transport-layer weakness for kubelet API traffic. This is CIS Kubernetes Benchmark control 4.2.13.

## How Checkov evaluates this
The check (`KubeletCryptographicCiphers`) maintains an allow-list of eight strong cipher suite names:
`TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`, `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`, `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305`, `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`, `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305`, `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`, `TLS_RSA_WITH_AES_256_GCM_SHA384`, `TLS_RSA_WITH_AES_128_GCM_SHA256`.

For each container's `command`, if `kubelet` is invoked:
1. It finds any argument starting with `--tls-cipher-suites`, splits on `=` to get the comma-separated list of cipher names.
2. If **any** listed cipher is not in the allow-list above, the check **FAILS**.
3. If the flag is absent, or all listed ciphers are in the allow-list, the check **PASSES** (an absent flag is treated as compliant, since it lets the kubelet apply its own reasonable default cipher set).

## Non-compliant example
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kubelet-static-pod
spec:
  containers:
    - name: kubelet
      image: k8s.gcr.io/hyperkube:v1.20.0
      command:
        - kubelet
        - --tls-cipher-suites=TLS_RSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
```

## Remediated example
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kubelet-static-pod
spec:
  containers:
    - name: kubelet
      image: k8s.gcr.io/hyperkube:v1.20.0
      command:
        - kubelet
        - --tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305
```

## Remediation steps
1. If `--tls-cipher-suites` is set, restrict its value to only ciphers from the approved strong list (see above), or remove the flag to let the kubelet use its secure built-in defaults.
2. In the `KubeletConfiguration` file, set `tlsCipherSuites` to the same restricted list if managing via config file rather than flags.
3. Confirm any clients that connect to the kubelet API (primarily the API server, and any monitoring tooling scraping kubelet metrics over TLS) support at least one of the allowed cipher suites — test in a staging environment before a fleet-wide rollout, since an overly restrictive cipher list could break connectivity for clients using older TLS libraries.
4. Roll out per node and restart the kubelet; monitor for TLS handshake failures in API server and kubelet logs immediately after the change.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/KubeletCryptographicCiphers.py
