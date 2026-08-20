# CKV_K8S_80: Ensure that the admission control plugin AlwaysPullImages is set
## Severity
**MEDIUM** (score: 5.0/10)

Without AlwaysPullImages, containers can reuse locally cached images without re-authenticating pull credentials, risking access to images an identity is no longer authorized to use and undermining image-based access control.

## Summary
This check fails a `kube-apiserver` container manifest unless `AlwaysPullImages` is included in its `--enable-admission-plugins` value, meaning the API server does not force kubelets to always re-pull (and re-authenticate against) container images before running them.

## Applicability
Kubernetes manifests where a container's `command` runs `kube-apiserver`, evaluated across container-bearing kinds (`CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`) — in practice, a self-managed/on-prem control-plane static pod manifest for `kube-apiserver`.

## Why it matters
Without `AlwaysPullImages`, a kubelet may run a pod using a locally-cached image without re-verifying the requester's access to the image registry — meaning that if an image was ever pulled to a node using one user's/workload's registry credentials, any other pod scheduled to that same node that references the same image tag/name can use the cached image without its own valid pull credentials or authorization check. In a multi-tenant cluster (shared nodes across teams/customers), this can let a tenant without legitimate registry access run a private image simply because it's already cached on a node another tenant's pod pulled it to — a form of credential/authorization bypass via image cache reuse. Enabling `AlwaysPullImages` forces every pod start to go through image pull authorization again, closing this gap. This is CIS Kubernetes Benchmark 1.2.12 (relevant primarily to multi-tenant/shared-node clusters).

## How Checkov evaluates this
`ApiServerAlwaysPullImagesPlugin.py`: if `command` contains `"kube-apiserver"`, it scans command tokens:
- If a token is exactly `"--enable-admission-plugins"` (no `=value`) → FAILED immediately.
- If a token contains `=`, split into `field`/`value`; if `field == "--enable-admission-plugins"` and `"AlwaysPullImages"` is **not** a substring of `value` → FAILED.
- If neither the bare flag nor a matching `=` token appears → PASSED (loop completes without triggering failure).

Note: the check uses substring containment (`"AlwaysPullImages" not in value`), so it does correctly match `AlwaysPullImages` combined with other plugins in a comma-separated value (e.g. `NodeRestriction,AlwaysPullImages`), unlike the exact-match logic in CKV_K8S_79.

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
    - --enable-admission-plugins=NodeRestriction,ResourceQuota   # AlwaysPullImages missing -> FAILS
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
    - --enable-admission-plugins=NodeRestriction,ResourceQuota,AlwaysPullImages
```

## Remediation steps
1. Add `AlwaysPullImages` to the `--enable-admission-plugins` comma-separated list on the API server.
2. Ensure every pod spec that needs a private image sets `imagePullSecrets` correctly, since `AlwaysPullImages` will now enforce the pull authorization check on every pod start rather than allowing cache reuse — pods missing valid credentials will fail to start where they may have previously succeeded via cache.
3. Understand the tradeoff: this increases image-pull traffic/latency (every pod start re-pulls, subject to the registry and kubelet's pull policy/cache behavior) in exchange for stronger per-pod authorization guarantees — most valuable in multi-tenant/shared-node environments; less critical in single-tenant clusters with trusted workloads only.
4. Test in staging first, watching for pod start failures due to previously-unnoticed missing `imagePullSecrets`.
5. Re-scan with `checkov -d . --check CKV_K8S_80`.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/ApiServerAlwaysPullImagesPlugin.py)
- [Kubernetes Admission Controllers reference](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#alwayspullimages)
