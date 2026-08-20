# CKV_K8S_104: Ensure that encryption providers are appropriately configured
## Severity
**HIGH** (score: 7.5/10)

Without configured encryption providers, Kubernetes Secrets are stored as plaintext in etcd, so anyone with etcd access or an etcd backup obtains all cluster secrets in the clear.

## Summary
This check ensures the Kubernetes API server is started with `--encryption-provider-config`, enabling encryption-at-rest for Secrets (and any other configured resource types) stored in etcd.

## Applicability
**Checkov framework(s):** `kubernetes`

Applies to Kubernetes manifests defining container specs for workload kinds (`CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`) — relevant specifically to the static Pod manifest running `kube-apiserver`, since the check looks for the `kube-apiserver` command.

## Why it matters
By default, Kubernetes stores all object data — including Secrets — in etcd as **plaintext**, encoded but not encrypted. Anyone who obtains read access to the etcd data store or its disk/volume snapshots (via a backup, a compromised control-plane node, an exposed etcd client port, or a misconfigured etcd access-control setup) can read every Secret in the cluster in cleartext: database passwords, TLS private keys, API tokens, service account tokens, cloud credentials, and so on. Configuring `--encryption-provider-config` on the API server enables it to transparently encrypt resource data (typically Secrets, and optionally ConfigMaps and other types) before it's written to etcd, using a configured provider (e.g., AES-CBC, AES-GCM, or an external KMS-backed provider like a cloud KMS or HashiCorp Vault transit engine). This means an attacker who gains raw etcd data access — without additionally compromising the API server's encryption key or the external KMS — obtains only ciphertext instead of every credential in the cluster. This is a foundational secrets-management control and corresponds to CIS Kubernetes Benchmark control 1.2.33/1.2.34.

## How Checkov evaluates this
`ApiServerEncryptionProviders` (a `BaseK8sContainerCheck`) extracts the container's command-line flags via `extract_commands`:
- If the container's command includes `kube-apiserver` and the extracted flag keys do **not** include `--encryption-provider-config`, the check **FAILS**.
- In every other case — not the API server container, or `--encryption-provider-config` is present — the check **PASSES**.
- The check only verifies the flag's presence; it does not inspect the referenced encryption config file's contents (e.g., which provider/KMS is used, or whether `identity` is listed first, which would effectively disable encryption).

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
        - --service-cluster-ip-range=10.96.0.0/12
        # missing --encryption-provider-config -> Secrets stored in cleartext in etcd
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
        - --service-cluster-ip-range=10.96.0.0/12
        - --encryption-provider-config=/etc/kubernetes/enc/encryption-config.yaml   # fix
      volumeMounts:
        - name: encryption-config
          mountPath: /etc/kubernetes/enc
          readOnly: true
  volumes:
    - name: encryption-config
      hostPath:
        path: /etc/kubernetes/enc
        type: Directory
```

Example `encryption-config.yaml` referenced above:
```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: <base64-encoded-32-byte-key>
      - identity: {}
```

## Remediation steps
1. Create an `EncryptionConfiguration` file specifying which resource types to encrypt (at minimum `secrets`) and which provider to use (`aescbc`, `aesgcm`, `kms` for cloud/Vault KMS integration — `kms` is strongly preferred over local static keys for production, since it avoids storing the raw encryption key on control-plane disk).
2. Mount that config file into the `kube-apiserver` static Pod and add `--encryption-provider-config=<path>` to its command args.
3. List `identity: {}` **last**, not first, in the `providers` list — if `identity` (no encryption) is listed first, new writes are stored unencrypted even though the flag is technically set; Checkov's presence-only check will not catch this misconfiguration, so verify it manually.
4. After enabling encryption, existing Secrets remain in their previous (plaintext) form in etcd until rewritten — run `kubectl get secrets --all-namespaces -o json | kubectl replace -f -` (or the documented `kube-apiserver` encryption migration procedure) to force re-encryption of all existing Secrets.
5. Securely back up the encryption key(s)/KMS configuration — losing them makes previously encrypted data permanently unreadable, and rotate keys periodically following your key-management policy.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/ApiServerEncryptionProviders.py)
- [Kubernetes docs: Encrypting Confidential Data at Rest](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
