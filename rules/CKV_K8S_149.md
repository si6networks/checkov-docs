# CKV_K8S_149: Ensure that the --rotate-certificates argument is not set to false
## Severity
**HIGH** (score: 7.5/10)

Disabling automatic kubelet certificate rotation (--rotate-certificates=false) lets node client certificates expire or remain unrotated, increasing the operational window for credential misuse if a certificate is ever compromised.

## Summary
This check ensures the kubelet does not have automatic client certificate rotation disabled (`--rotate-certificates=false`), so its client certificates are renewed automatically before they expire.

## Applicability
Kubernetes manifests for workload kinds carrying a pod template: `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`. It inspects the container `command` array, acting when it invokes `kubelet`.

## Why it matters
`--rotate-certificates` enables the kubelet to automatically request a new client certificate from the API server's certificates API as its current one approaches expiry, replacing it seamlessly. If disabled, kubelet client certificates will eventually expire, and operators must manually intervene to reissue and redistribute them — a manual process that is error-prone and easy to neglect at scale. An expired client certificate causes the kubelet to lose its ability to authenticate to the API server, taking the node effectively out of cluster management (kubelet cannot register status, receive pod assignments, or report health), a reliability/availability failure that in an incident could also make it harder to promptly identify and re-secure affected nodes. Beyond availability, automatic rotation also limits the exposure window of any given certificate/key material, supporting good credential hygiene. CIS Kubernetes Benchmark control 4.2.11 recommends leaving this enabled (not explicitly disabled).

## How Checkov evaluates this
The check (`KubletRotateCertificates`) looks at each container's `command` list:
1. If `kubelet` is among the command tokens, it checks whether the exact string `--rotate-certificates=false` appears in the command list.
2. If it does, the check **FAILS**.
3. Otherwise (flag absent — which defaults to rotation enabled in modern kubelet versions — or explicitly set to `true`), the check **PASSES**.

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
        - --rotate-certificates=false
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
        - --rotate-certificates=true
```

## Remediation steps
1. Remove `--rotate-certificates=false` from the kubelet command line, or set it explicitly to `true` (or `rotateCertificates: true` in `KubeletConfiguration`).
2. Ensure the API server's controller manager has the `csrapprover`/certificate-signing controllers enabled and, ideally, automatic CSR approval configured for kubelet client-cert renewals (via RBAC on `certificatesigningrequests` and the `approve`/`sign` subresources) — see also CKV_K8S_156 for restricting who can approve CSRs.
3. Verify TLS bootstrapping is properly configured (bootstrap tokens or equivalent) since rotation relies on the same certificate-issuance pipeline.
4. Roll out per node and monitor certificate expiry dates/renewal events (`kubectl get csr`) to confirm rotation is actually occurring before relying on it.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/KubletRotateCertificates.py
- Kubernetes docs on kubelet certificate rotation: https://kubernetes.io/docs/tasks/tls/certificate-rotation/
