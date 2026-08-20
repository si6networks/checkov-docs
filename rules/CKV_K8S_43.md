# CKV_K8S_43: Image should use digest

## Severity
**LOW** (score: 2.0/10)

Referencing images by mutable tag rather than immutable digest creates a supply-chain integrity gap (a tag can be repointed to different content later), but exploiting it requires a separate compromise of the registry or build pipeline, making this primarily a hygiene/traceability control.

## Summary
This check ensures container images are referenced by their immutable content digest (`@sha256:...`) rather than only by a mutable tag.

## Applicability
- **Kubernetes manifests**: container-level check across kinds `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`.
- **Terraform**: resource types `kubernetes_pod`, `kubernetes_pod_v1`, `kubernetes_deployment`, `kubernetes_deployment_v1`, at `spec.container[].image`.

## Why it matters
Image tags (including seemingly-pinned ones like `v1.4.0`, not just `latest`) are mutable pointers in most registries — the same tag can be overwritten to point at a different, potentially malicious or vulnerable, image at any time, whether by a compromised CI pipeline, a compromised upstream maintainer account, or simple human error. Referencing an image by its cryptographic digest (`image@sha256:<hash>`) pins the exact byte-for-byte content that will be pulled and run, guaranteeing reproducibility across environments (dev/staging/prod all run the identical, verified artifact) and closing off "tag substitution" as a supply-chain attack vector — an attacker who compromises a registry account and re-pushes a backdoored image under an existing tag cannot silently redirect deployments that pin by digest. This is especially important combined with image-signing/verification tooling (e.g. Cosign/Sigstore), which typically verifies against a digest.

## How Checkov evaluates this
For each container, the check inspects the `image` field as a string: if it contains an `@` character (indicating a digest reference, e.g. `myrepo/app@sha256:abcd...`), the check PASSES. If there is no `@` in the image reference (i.e. only a tag or no tag at all, which implicitly means `:latest`), it FAILS.

## Non-compliant example
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      containers:
        - name: app
          image: myrepo/web:1.4.0
```

## Remediated example
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      containers:
        - name: app
          image: myrepo/web:1.4.0@sha256:9c2b3d1e6a4f... # pinned by digest
```

## Remediation steps
1. Resolve the digest for the currently-used tag: `docker inspect --format='{{index .RepoDigests 0}}' myrepo/web:1.4.0`, or pull the manifest via `crane digest myrepo/web:1.4.0` / `docker buildx imagetools inspect`.
2. Reference the image as `<repo>/<image>@sha256:<digest>` (optionally keep the tag alongside the digest for human readability, e.g. `myrepo/web:1.4.0@sha256:...`).
3. Automate digest pinning in CI/CD (e.g. using tools like `digester`, Renovate/Dependabot digest-pinning support, or a Kustomize `images:` transformer that resolves and injects digests) so manifests stay current without manual digest lookups on every release.
4. Update the flagged `observability`, `dash`, and `cert-manager` kustomization bases in this repo to pin digests, and confirm the CI/CD promotion pipeline re-resolves digests on each build rather than leaving stale ones checked in.
5. Combine with image-signature verification (e.g. Sigstore/Cosign + an admission controller) for stronger supply-chain guarantees beyond digest pinning alone.

## References
- [Checkov check source (Kubernetes)](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/ImageDigest.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/kubernetes/ImageDigest.py)
- [Kubernetes docs: Images](https://kubernetes.io/docs/concepts/containers/images/)
