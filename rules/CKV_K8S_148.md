# CKV_K8S_148: Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate
## Severity
**HIGH** (score: 7.5/10)

Without --tls-cert-file and --tls-private-key-file configured, the kubelet API server may serve over unauthenticated/unencrypted or self-generated certificates, exposing node management traffic to interception or spoofing.

## Summary
This check ensures the kubelet is configured with both `--tls-cert-file` and `--tls-private-key-file` so its HTTPS API is served with a proper TLS certificate/key pair rather than a kubelet-generated self-signed one.

## Applicability
**Checkov framework(s):** `kubernetes`

Kubernetes manifests for workload kinds carrying a pod template: `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`. It inspects the container `command` array, acting when it invokes `kubelet`.

## Why it matters
The kubelet serves its API over HTTPS. If `--tls-cert-file`/`--tls-private-key-file` are not explicitly set, the kubelet auto-generates a self-signed certificate at startup. Self-signed, auto-generated certificates are not chained to a trusted CA, cannot be centrally managed/rotated, and make it easy for clients (and attackers performing MITM) to be tricked into trusting an unverifiable endpoint, since there's no consistent chain of trust to validate against. Explicitly provisioning certificates signed by a proper (cluster) CA allows clients to validate the kubelet's identity cryptographically, supports certificate rotation and revocation, and is required for a coherent cluster-wide TLS trust model. This is CIS Kubernetes Benchmark control 4.2.10 — properly set TLS material on the kubelet closes a gap that could otherwise let an attacker impersonate or intercept traffic to a node's kubelet API.

## How Checkov evaluates this
The check (`KubeletKeyFilesSetAppropriate`) looks at each container's `command` list:
1. If `kubelet` is among the command tokens, it scans every command argument.
2. It sets `hasTLSCert = True` if any argument starts with `--tls-cert-file`, and `hasTLSKey = True` if any argument starts with `--tls-private-key-file`.
3. If both are true, the check **PASSES**; if either is missing, it **FAILS**. (Note it does not validate the value is non-empty, only that the flag is present.)
4. If the command doesn't invoke `kubelet` at all, the check **PASSES** (not applicable).

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
        - --tls-cert-file=/var/lib/kubelet/pki/kubelet.crt
        # --tls-private-key-file missing
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
        - --tls-cert-file=/var/lib/kubelet/pki/kubelet.crt
        - --tls-private-key-file=/var/lib/kubelet/pki/kubelet.key
```

## Remediation steps
1. Provision a proper TLS certificate/key pair for each kubelet, issued by your cluster CA (many distributions do this automatically via kubelet TLS bootstrapping — verify it's enabled rather than falling back to self-signed generation).
2. Set `--tls-cert-file` and `--tls-private-key-file` to the correct file paths on the node, or the equivalent `tlsCertFile`/`tlsPrivateKeyFile` fields in the `KubeletConfiguration` file.
3. Ensure file permissions restrict the private key to the kubelet process/root only (e.g., `0600`).
4. Set up certificate rotation (`--rotate-certificates=true`, see CKV_K8S_149) so these files stay current without manual intervention.
5. Restart the kubelet per node and verify the API server can still communicate with it over the newly configured TLS material before rolling out cluster-wide.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/KubeletKeyFilesSetAppropriate.py
