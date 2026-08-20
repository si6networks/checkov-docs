# CKV_AZUREPIPELINES_1: Ensure container job uses a non latest version tag

## Severity
**MEDIUM** (score: 5.5/10)

Using a floating 'latest' tag for a container job means the exact image content is not pinned, allowing unreviewed or unexpectedly changed image content to be pulled into the pipeline, a supply-chain integrity weakness.

## Summary
This check fails when a job (or a job nested inside a stage) in an Azure Pipelines YAML file runs its container image with either no tag at all (defaults to `:latest`) or an explicit `:latest` tag, instead of pinning to a specific version.

## Applicability
**Checkov framework(s):** `azure_pipelines`

- **Azure Pipelines** YAML pipeline definitions — applies to the `jobs` and `stages[].jobs[]` entities, specifically their `container` field (either a plain image string or a `container.image` object field).

## Why it matters
Using the `latest` tag (implicitly or explicitly) for a pipeline's container job means the exact image content is not pinned — a `docker pull` for `latest` (or an untagged reference) can silently resolve to a different image than what was used in a previous run, at any time, without any corresponding change in the pipeline definition. This breaks build reproducibility (the same pipeline YAML can produce different results on different days) and is a supply-chain risk: if the upstream image publisher's `latest` tag is compromised (maliciously or accidentally, e.g. a broken release pushed to `latest`), every pipeline run using that tag picks up the compromised image automatically, with no version control history showing that anything changed. This is the same class of risk addressed by Docker/Kubernetes "don't use :latest in production" guidance, applied here to CI/CD job containers, which have privileged access to source code, secrets, and artifact publishing.

## How Checkov evaluates this
For each `jobs`/`stages[].jobs[]` entry, the check reads the `container` field. If `container` is a dict/object, it extracts `container.image`; if it's already a string, it's used directly. Then:
- If the resulting image string contains a `:` (a tag separator), and the portion after the colon is exactly `latest` → **FAILED**.
- If there is no `:` in the string and also no `@` (i.e., no tag and no digest reference) → **FAILED** (an untagged image defaults to `latest`).
- Otherwise (a non-`latest` tag, or a `@sha256:...` digest reference) → **PASSED**.
- If there is no `container` field at all → **UNKNOWN** (the job isn't running a container, so the check doesn't apply).

## Non-compliant example
```yaml
jobs:
  - job: build
    pool:
      vmImage: 'ubuntu-latest'
    container: node:latest
    steps:
      - script: npm install && npm test
```

## Remediated example
```yaml
jobs:
  - job: build
    pool:
      vmImage: 'ubuntu-latest'
    container: node:20.11.1
    steps:
      - script: npm install && npm test
```

## Remediation steps
1. Replace any `container: <image>:latest` or untagged `container: <image>` reference with a specific version tag (e.g., `node:20.11.1`, `python:3.12-slim`).
2. Prefer pinning to an immutable digest (`image@sha256:...`) where reproducibility guarantees matter most — this also satisfies the related check CKV_AZUREPIPELINES_2.
3. Establish a process (e.g., Dependabot/Renovate, or a scheduled pipeline) to deliberately bump pinned versions rather than relying on `latest` to "auto-update," so upgrades are visible, reviewable, and revertible in version control.
4. Apply the same pinning discipline to any container references nested under `resources.containers` used by the pipeline.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/azure_pipelines/checks/job/ContainerLatestTag.py
- Azure Pipelines docs: https://learn.microsoft.com/en-us/azure/devops/pipelines/process/container-phases
