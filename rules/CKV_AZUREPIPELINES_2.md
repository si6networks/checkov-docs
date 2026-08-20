# CKV_AZUREPIPELINES_2: Ensure container job uses a version digest

## Severity
**MEDIUM** (score: 6.0/10)

Referencing a container by mutable tag instead of an immutable digest allows the actual image content to change without the pipeline definition changing, undermining supply-chain integrity guarantees for what code actually executes.

## Summary
This check fails when a job's `container` field in an Azure Pipelines YAML file references an image by tag rather than by an immutable content digest (`@sha256:...`).

## Applicability
**Checkov framework(s):** `azure_pipelines`

- **Azure Pipelines** YAML pipeline definitions — applies to the `jobs` and `stages[].jobs[]` entities, specifically their `container` field.

## Why it matters
Image tags (including specific version tags like `node:20.11.1`, not just `latest`) are mutable pointers — a registry maintainer (or an attacker who compromises the registry account or CI process that publishes the image) can re-push a different image under the same tag at any time. A digest (`sha256:...`) is a cryptographic hash of the actual image content, so referencing `image@sha256:<hash>` guarantees the exact same bytes are pulled every time, regardless of what happens to the tag afterward. For CI/CD pipeline containers specifically — which typically have access to source code, build secrets, and signing/publishing credentials — this matters because an image substitution attack (tag hijack) executed inside the pipeline's container could exfiltrate secrets or inject malicious code into build artifacts, all without any visible change to the pipeline YAML. Digest pinning closes this specific supply-chain gap; tag pinning alone (addressed by CKV_AZUREPIPELINES_1) only protects against the narrower case of using `latest`.

## How Checkov evaluates this
Reads the `container` field for each job. If it is a string containing `@` (the digest separator, e.g. `image@sha256:...`) → **PASSED**. If it's a string without `@` (whether tagged with a version or untagged) → **FAILED**. If there is no `container` field at all → **UNKNOWN**.

## Non-compliant example
```yaml
jobs:
  - job: build
    pool:
      vmImage: 'ubuntu-latest'
    container: node:20.11.1
    steps:
      - script: npm install && npm test
```

## Remediated example
```yaml
jobs:
  - job: build
    pool:
      vmImage: 'ubuntu-latest'
    container: node:20.11.1@sha256:6c9c33f5e2f8b5c3f0a5f8a1e0e0a1c9b8f3d2a1c0e9d8c7b6a5f4e3d2c1b0a9
    steps:
      - script: npm install && npm test
```

## Remediation steps
1. Resolve the digest for the image/tag currently in use, e.g. `docker pull node:20.11.1 && docker inspect --format='{{index .RepoDigests 0}}' node:20.11.1`, or read it from the registry's UI/API.
2. Replace `image:tag` with `image:tag@sha256:<digest>` (keeping the tag alongside the digest is allowed and improves human readability while the digest still pins the exact content).
3. Update the pinned digest deliberately (via a reviewed PR) whenever the base image needs an intentional upgrade — e.g., using Renovate/Dependabot with digest-pinning support, which can automate digest bumps as PRs.
4. Apply the same digest-pinning practice to any images referenced under the pipeline's `resources.containers` block, not just inline `container:` fields on jobs.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/azure_pipelines/checks/job/ContainerDigest.py
- Docker docs on image digests: https://docs.docker.com/reference/cli/docker/image/pull/#pull-an-image-by-digest-immutable-identifier
