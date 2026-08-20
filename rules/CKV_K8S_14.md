# CKV_K8S_14: Image Tag should be fixed - not latest or blank
## Severity
**LOW** (score: 2.0/10)

Using a mutable `latest`/blank image tag undermines deployment integrity and rollback, letting a compromised or unexpected image version be pulled without an explicit, auditable reference.

## Summary
This check requires every container image reference to use a specific, immutable tag (or digest) instead of the mutable `:latest` tag or an omitted tag (which also defaults to `latest`).

## Applicability
**Checkov framework(s):** `kubernetes`, `terraform`

- **Kubernetes** manifests: workload kinds with a container spec — `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`.
- **Terraform**: `kubernetes_deployment`, `kubernetes_deployment_v1`, `kubernetes_pod`, `kubernetes_pod_v1` resources.
In both cases it inspects each container's `image` field.

## Why it matters
Using `:latest` (or no tag) means the exact image content deployed is not pinned — a redeploy, node reschedule, or pod restart can silently pull a newer (or different) image than what was previously running, without any code or manifest change to review. This breaks reproducibility, defeats rollback (you cannot roll back to "latest" because the tag doesn't identify a fixed artifact), and makes incident forensics and vulnerability tracking far harder because you cannot definitively say which image digest was running at a given time. It also opens a supply-chain risk: if a base or application image `latest` tag is overwritten upstream (accidentally or maliciously), every node pulling `latest` afterward gets the new content immediately and without independent verification, with no way to detect drift between environments. Pinning to a specific tag (or better, a content digest) makes deployments deterministic and auditable.

## How Checkov evaluates this
**Kubernetes check** (`ImageTagFixed`): for each container's `image` value:
- If the value isn't a non-empty string, result is `UNKNOWN`.
- If it contains `@` (a digest reference), it **PASSES** immediately (a digest is even stronger than a tag).
- Otherwise it parses the image with `DOCKER_IMAGE_REGEX` to extract `(image, tag)`. If the tag is `latest` or empty, it **FAILS**; any other explicit tag **PASSES**.
- Missing `image` field entirely → **FAILS**.

**Terraform check**: walks `spec` (unwrapping `template.spec` for Deployments) to reach each `container` block. For each container's `image` attribute:
- If it contains a `:` and the part after the colon is `latest` or empty → **FAILS**.
- If it contains `@` (digest) → treated as compliant, continues to next container.
- No `image` attribute at all → **FAILS**.

## Non-compliant example
```yaml
# Kubernetes
apiVersion: apps/v1
kind: Deployment
metadata:
  name: dash
spec:
  replicas: 2
  selector:
    matchLabels:
      app: dash
  template:
    metadata:
      labels:
        app: dash
    spec:
      containers:
        - name: dash
          image: myregistry/dash:latest
```

```hcl
# Terraform
resource "kubernetes_deployment" "dash" {
  spec {
    template {
      spec {
        container {
          name  = "dash"
          image = "myregistry/dash"  # no tag -> defaults to latest
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
  name: dash
spec:
  replicas: 2
  selector:
    matchLabels:
      app: dash
  template:
    metadata:
      labels:
        app: dash
    spec:
      containers:
        - name: dash
          image: myregistry/dash:1.4.2   # fixed, immutable tag
          # or: image: myregistry/dash@sha256:abcdef...  (digest, strongest)
```

```hcl
resource "kubernetes_deployment" "dash" {
  spec {
    template {
      spec {
        container {
          name  = "dash"
          image = "myregistry/dash:1.4.2"
        }
      }
    }
  }
}
```

## Remediation steps
1. Identify every `image:` field in the affected manifests (the `kustomization.yaml` files listed above are the entry points that set `images:` overrides for kustomize — check their `newTag`/`images` sections too).
2. Replace `latest` or blank tags with a specific semantic version, build number, or commit-SHA-based tag that your CI pipeline produces.
3. Prefer pinning by digest (`image@sha256:...`) for maximum immutability where your registry and CI can supply/verify digests.
4. Update your CI/CD to always publish a uniquely tagged image per build and to update the manifest/kustomization tag as part of the release process, rather than repeatedly pushing `latest`.
5. For kustomize overlays (`dev`, `prod`), ensure each overlay's `images:` transformer pins to an explicit tag rather than inheriting `latest` from the base.
6. No downtime/replacement risk from this fix alone, but rolling out a new pinned tag will trigger a normal rolling deployment — verify readiness/liveness probes are in place.

## References
- Checkov check source (Kubernetes): https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/ImageTagFixed.py
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/kubernetes/ImageTagFixed.py
- Kubernetes docs on image pull policy and tags: https://kubernetes.io/docs/concepts/containers/images/
