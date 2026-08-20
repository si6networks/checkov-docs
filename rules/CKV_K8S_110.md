# CKV_K8S_110: Ensure that the --service-account-private-key-file argument is set as appropriate
## Severity
**HIGH** (score: 7.5/10)

The --service-account-private-key-file underpins the signing of every service account token in the cluster, so an improperly configured or missing key file undermines the integrity of the cluster-wide token trust chain.

## Summary
This check verifies that when `kube-controller-manager` specifies a `--service-account-private-key-file`, that file has a `.pem` extension, which Checkov treats as the marker of a properly-provisioned private key file for the service account token controller.

## Applicability
**Checkov framework(s):** `kubernetes`

Kubernetes manifests defining a Pod-carrying workload whose container `command` invokes `kube-controller-manager` — applicable entity kinds are `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`. In practice it only meaningfully evaluates the static Pod manifest for the `kube-controller-manager` control-plane component.

## Why it matters
`--service-account-private-key-file` points `kube-controller-manager`'s service-account token controller at the private key used to sign every ServiceAccount token issued in the cluster. This is one of the most sensitive files in the entire cluster: anyone who obtains it can mint valid, unexpired ServiceAccount tokens for any identity, bypassing Kubernetes' authentication layer entirely. Ensuring this argument is explicitly and correctly configured (pointing at a real PEM-encoded key rather than being left unset, misconfigured, or pointed at the wrong artifact) is a CIS Kubernetes Benchmark control-plane hardening item — misconfiguration here can silently break ServiceAccount token issuance/rotation or, worse, point at an insecure/predictable key material path.

## How Checkov evaluates this
The check (`KubeControllerManagerServiceAccountPrivateKeyFile`) inspects the container's `command` list:
- If `command` is absent, or does not include `kube-controller-manager`, the check **PASSES** (not applicable).
- If `kube-controller-manager` is present, it scans tokens for one starting with `--service-account-private-key-file`. When found, it takes the value after `=`, splits on `.` and takes the second segment as the file extension.
  - If the extension is exactly `pem`, it **PASSES**.
  - Otherwise it **FAILS**.
  - Note: if the flag is never present at all, the function falls through without an explicit return in that branch and Checkov treats the check as **PASSED** by default (only an explicit non-`.pem` value triggers FAILED) — so this check only catches the case where the flag is set but not pointing at a `.pem` file, not the case where the flag is entirely missing.

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
    - --service-account-private-key-file=/etc/kubernetes/pki/sa.key.bak
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
    - --service-account-private-key-file=/etc/kubernetes/pki/sa.key.pem
```

## Remediation steps
1. Locate the static Pod manifest for `kube-controller-manager` (typically `/etc/kubernetes/manifests/kube-controller-manager.yaml`).
2. Confirm `--service-account-private-key-file` points at the cluster's actual PEM-encoded service-account signing key (kubeadm defaults to `/etc/kubernetes/pki/sa.key`, but note the Checkov extension check literally requires a filename ending in `.pem` — rename or symlink accordingly if your key file uses a different suffix such as `.key`).
3. Restrict filesystem permissions on the key file to `0600`, owned by root, and never commit it to source control.
4. Rotate the key (and re-issue all ServiceAccount tokens) if you suspect it has ever been exposed.
5. Save the manifest — kubelet restarts the static Pod automatically to pick up changes.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/KubeControllerManagerServiceAccountPrivateKeyFile.py)
- [Kubernetes: Managing Service Accounts](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/)
