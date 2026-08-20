# CKV_K8S_15: Image Pull Policy should be Always
## Severity
**LOW** (score: 2.0/10)

An imagePullPolicy other than Always is primarily an operational-consistency concern (risk of running a stale locally-cached image) rather than a directly exploitable security control.

## Summary
This check ensures containers using a mutable image reference (no digest, and a tag other than `latest`) explicitly set `imagePullPolicy: Always`, so the node always pulls the current image rather than reusing a potentially stale locally cached copy.

## Applicability
**Checkov framework(s):** `kubernetes`, `terraform`

- **Kubernetes** manifests: workload kinds with a container spec — `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`.
- **Terraform**: `kubernetes_deployment`, `kubernetes_deployment_v1`, `kubernetes_pod`, `kubernetes_pod_v1` resources.
Inspects each container's `image` and `imagePullPolicy` fields.

## Why it matters
Kubernetes' default `imagePullPolicy` depends on the tag: it is `Always` only when the tag is `latest` or omitted, and `IfNotPresent` for any other explicit tag. `IfNotPresent` means the kubelet will reuse whatever image with that name+tag is already cached locally on the node instead of re-pulling from the registry — even if the registry content behind that tag has since changed, or if a different (possibly malicious or vulnerable) image was previously cached under the same name/tag by another workload. This can cause nodes in the same cluster to run inconsistent image content under an identical tag reference, undermines assumptions that a given tag corresponds to a known-good, verified artifact, and can be leveraged in image-cache poisoning-style attacks where an attacker who can get a malicious image cached under a trusted tag name causes it to persist and be reused. It also complicates image pull secret validation — because with `IfNotPresent`, if the image is already cached, the pull secret is never checked at all, silently masking registry access/permission problems and potentially allowing a stale image to run even after credentials protecting the real registry copy have been revoked. Explicitly setting `imagePullPolicy: Always` forces a fresh pull (and pull-secret/authorization check) on every pod start.

## How Checkov evaluates this
**Kubernetes check** (`ImagePullPolicyAlways`): for each container:
1. If `image` is missing/blank/not a string → `FAILED`/`UNKNOWN` as appropriate.
2. Strip any `@digest` suffix; note whether a digest was present.
3. If `imagePullPolicy` is **not set** on the container: parse the image's tag. If tag is `latest` or blank → `PASSED` (default pull policy is `Always` in this case). If a digest was present → `PASSED`. Otherwise (explicit non-latest tag, no digest, no explicit policy) → `FAILED` (default pull policy is `IfNotPresent`).
4. If `imagePullPolicy` **is set**: passes only if it equals `Always`, unless a digest is present (digest-pinned images are considered acceptable regardless of policy) — otherwise `FAILED`.

**Terraform check**: walks to each `container` block (unwrapping Deployment `template.spec`). For each container: passes if `image_pull_policy == "Always"`, OR if no explicit policy is set but the image name contains `"latest"` or contains `"@"` (digest). Any other combination `FAILED`. Missing `container` blocks → `UNKNOWN`; missing `spec` → `FAILED`.

## Non-compliant example
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: observability-agent
spec:
  template:
    spec:
      containers:
        - name: agent
          image: myregistry/agent:1.2.3   # explicit tag, no imagePullPolicy set
          # imagePullPolicy defaults to IfNotPresent here
```

```hcl
resource "kubernetes_deployment" "cert_manager" {
  spec {
    template {
      spec {
        container {
          name  = "cert-manager"
          image = "quay.io/jetstack/cert-manager-controller:v1.11.0"
          # no image_pull_policy set
        }
      }
    }
  }
}
```

## Remediated example
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: observability-agent
spec:
  template:
    spec:
      containers:
        - name: agent
          image: myregistry/agent:1.2.3
          imagePullPolicy: Always   # force fresh pull + pull-secret check every time
```

```hcl
resource "kubernetes_deployment" "cert_manager" {
  spec {
    template {
      spec {
        container {
          name              = "cert-manager"
          image             = "quay.io/jetstack/cert-manager-controller:v1.11.0"
          image_pull_policy = "Always"
        }
      }
    }
  }
}
```

## Remediation steps
1. Add `imagePullPolicy: Always` (Kubernetes YAML) or `image_pull_policy = "Always"` (Terraform `kubernetes_*` resources) to every container using a fixed, non-latest tag.
2. If you already pin images by digest (`@sha256:...`), this check is satisfied regardless of pull policy since the digest itself guarantees content immutability — consider migrating to digest pinning as the stronger long-term fix (works well combined with CKV_K8S_14).
3. Be aware `imagePullPolicy: Always` increases registry pull traffic (a pull attempt on every pod start/restart) — ensure your registry can handle this load and that pull-secret credentials stay valid and are rotated properly, since failures will now block pod starts rather than silently reusing cache.
4. Update the affected kustomize bases/overlays (`observability`, `cert-manager`, `argo`) to add the policy at the base level unless environment-specific overrides are needed.
5. No resource replacement required — this is a rolling-update-safe field change.

## References
- Checkov check source (Kubernetes): https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/ImagePullPolicyAlways.py
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/kubernetes/ImagePullPolicyAlways.py
- Kubernetes docs on image pull policy: https://kubernetes.io/docs/concepts/containers/images/#image-pull-policy
