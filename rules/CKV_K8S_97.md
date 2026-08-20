# CKV_K8S_97: Ensure that the --service-account-key-file argument is set as appropriate
## Severity
**MEDIUM** (score: 5.0/10)

Without a service-account key file configured, the API server cannot properly verify service account tokens, undermining a key workload-identity authentication mechanism used throughout the cluster.

## Summary
This check verifies that if a self-managed `kube-apiserver` container sets `--service-account-key-file`, its value points to a `.pem`-suffixed file path used for validating ServiceAccount tokens.

## Applicability
Kubernetes manifests only. Applies to pod-spec-bearing resources: `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`. Relevant only to the container spec of a self-hosted `kube-apiserver` static pod/manifest.

## Why it matters
`--service-account-key-file` specifies the public key(s) (PEM-encoded) used by the API server to verify ServiceAccount token signatures. A separate, explicitly-configured public key file (distinct from the general TLS serving certificate) allows an operator to rotate the ServiceAccount signing key independently from the API server's TLS certificate, and ensures the correct key material is being used for a security-critical verification path. Misconfiguring this — pointing at the wrong file, a non-PEM file, or omitting a value — can cause token validation to silently use unintended key material, potentially accepting forged tokens or, more commonly, breaking legitimate ServiceAccount authentication cluster-wide (a self-inflicted denial of service).

## How Checkov evaluates this
The check (`ApiServerServiceAccountKeyFile`, a `BaseK8sContainerCheck`) inspects the container's `command` list, using the pattern `^(.*)\.pem$`:
1. If `command` is missing, or doesn't contain `kube-apiserver`, returns PASSED.
2. If `kube-apiserver` is present, it scans each argument:
   - A bare `--service-account-key-file` with no value → FAILED.
   - `--service-account-key-file=<value>` → FAILED unless `<value>` ends in `.pem`.
3. If `--service-account-key-file` is never set, no failure condition is triggered and the check returns PASSED by default (the flag's absence isn't itself flagged, only a present-but-malformed value).

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
        - --service-account-key-file=/etc/kubernetes/pki/sa.key
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
        - --service-account-key-file=/etc/kubernetes/pki/sa.pub.pem
```

## Remediation steps
1. Ensure the file referenced by `--service-account-key-file` uses a `.pem` extension (rename or re-export the key material as needed — kubeadm typically names this `sa.pub`, which you may need to alias or copy to a `.pem`-suffixed path to satisfy this check).
2. Confirm the file actually contains a valid PEM-encoded public key matching the private key used by the controller manager's `--service-account-private-key-file` for signing tokens.
3. Mount the key file into the `kube-apiserver` static pod via a `hostPath` volume if it isn't already, since static pods don't use standard Secret mounting.
4. Test that existing ServiceAccount tokens are still accepted after any key-file path change — an incorrect key will cause all ServiceAccount-authenticated requests to fail with 401 Unauthorized.
5. If your organization has a naming convention that conflicts with the `.pem` suffix requirement, consider a symlink with the `.pem` extension pointing at the actual key file, provided your security policy allows it.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/ApiServerServiceAccountKeyFile.py)
- [Kubernetes API server options reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)
