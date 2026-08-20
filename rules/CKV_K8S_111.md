# CKV_K8S_111: Ensure that the --root-ca-file argument is set as appropriate
## Severity
**HIGH** (score: 7.5/10)

The --root-ca-file is distributed to pods via service account secrets to let them validate the API server's TLS certificate, so misconfiguring it weakens pod-to-API-server trust and opens the door to man-in-the-middle risk.

## Summary
This check verifies that when `kube-controller-manager` specifies a `--root-ca-file` argument, it points at a `.pem`-suffixed certificate file, so ServiceAccount tokens distributed to Pods include a valid root CA bundle for verifying the API server's TLS certificate.

## Applicability
**Checkov framework(s):** `kubernetes`

Kubernetes manifests defining a Pod-carrying workload whose container `command` invokes `kube-controller-manager` — applicable entity kinds are `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`. In practice it only meaningfully evaluates the static Pod manifest for the `kube-controller-manager` control-plane component.

## Why it matters
`--root-ca-file` tells the controller manager which CA certificate to inject into every namespace's `default` ServiceAccount token (and the `kube-root-ca.crt` ConfigMap), which in-cluster clients use to verify the API server's TLS certificate over HTTPS. If this is misconfigured or points at the wrong/incomplete CA bundle, workloads either can't validate the API server certificate (breaking legitimate in-cluster API access) or, worse, could be tricked into trusting an unintended/incorrect certificate authority, undermining TLS verification for in-cluster API traffic entirely (a man-in-the-middle risk). This is a CIS Kubernetes Benchmark control-plane hardening item ensuring the root CA distributed to workloads is deliberately and correctly configured.

## How Checkov evaluates this
The check (`KubeControllerManagerRootCAFile`) inspects the container's `command` list:
- If `command` is absent, or does not include `kube-controller-manager`, the check **PASSES** (not applicable).
- If `kube-controller-manager` is present, it scans tokens for one starting with `--root-ca-file`. When found, it takes the value after `=`, splits on `.`, and takes the second segment as the file extension.
  - If the extension is exactly `pem`, it **PASSES**.
  - Otherwise it **FAILS**.
  - As with CKV_K8S_110, if the flag is entirely absent, there is no explicit FAILED branch reached, so the check effectively only flags a present-but-wrongly-suffixed value, not a missing flag.

## Non-compliant example
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kube-controller-manager
  namespace: kube-system
spec:
  containers:
  - name: kube-controller-manager
    image: k8s.gcr.io/kube-controller-manager:v1.28.0
    command:
    - kube-controller-manager
    - --root-ca-file=/etc/kubernetes/pki/ca.crt
```

## Remediated example
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kube-controller-manager
  namespace: kube-system
spec:
  containers:
  - name: kube-controller-manager
    image: k8s.gcr.io/kube-controller-manager:v1.28.0
    command:
    - kube-controller-manager
    - --root-ca-file=/etc/kubernetes/pki/ca.pem
```

## Remediation steps
1. Locate the static Pod manifest for `kube-controller-manager` (typically `/etc/kubernetes/manifests/kube-controller-manager.yaml`).
2. Verify `--root-ca-file` points at the cluster's actual root CA certificate. Note that this Checkov check specifically requires the referenced filename to end in `.pem`; if your distribution uses `ca.crt` (very common with kubeadm), you may need a `.pem`-suffixed copy/symlink to satisfy the literal check, while confirming the underlying content is still the correct CA cert used elsewhere in the cluster's PKI (e.g. matches the CA that signed the API server serving certificate).
3. Confirm the file is readable only by the controller-manager process user and not world-readable.
4. Save the manifest — the static Pod restarts automatically to pick up the change.
5. After rotating a CA, confirm existing ServiceAccount tokens/ConfigMaps (`kube-root-ca.crt`) are refreshed cluster-wide so workloads don't lose API server trust.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/KubeControllerManagerRootCAFile.py)
- [Kubernetes PKI certificates and requirements](https://kubernetes.io/docs/setup/best-practices/certificates/)
