# CKV_GITLABCI_3: Detecting image usages in gitlab workflows
## Severity
**LOW** (score: 2.0/10)

This check's scan_conf() unconditionally returns PASSED, making it an informational image-usage inventory rather than a control that ever blocks an exploitable misconfiguration.

## Summary
This check inventories the container `image` and `services` entries used in GitLab CI job definitions. It is an informational/inventory check rather than a pass/fail security gate — it always reports as passing.

## Applicability
Applies to GitLab CI configuration files (`.gitlab-ci.yml`), specifically any job block's `image` and `services` array/scalar fields (matched via the wildcard entity patterns `*.image[]` and `*.services[]`).

## Why it matters
Tracking which container images a CI pipeline pulls and executes is foundational for supply-chain visibility. CI jobs run with significant privileges (access to repository secrets, deployment credentials, artifact registries), so an unpinned, unvetted, or unexpectedly-changed base image or service container used within a `.gitlab-ci.yml` job is a realistic vector for supply-chain compromise (e.g., a compromised or typosquatted image silently exfiltrating CI secrets, or a mutable `:latest` tag drifting to a malicious build in a way that isn't visible in code review). This check exists to surface every image reference so downstream tooling (Bridgecrew/Prisma Cloud platform features, custom policies, or manual review) can inventory, pin, and vet them — it is the enumeration step that other, more opinionated checks and the platform's SCA/image-scanning features build on.

## How Checkov evaluates this
Checkov's `DetectImageUsage` class is a `BaseGitlabCICheck` scoped to the entities `*.image[]` and `*.services[]` (i.e., it walks every job block in the pipeline YAML and inspects the `image:` field and the `services:` list, wherever they appear — job-level or global `default`). Unlike most Checkov checks, `scan_conf()` unconditionally returns `CheckResult.PASSED` for whatever configuration it is handed. There is no failure condition in the code — the check exists purely to extract and record the image reference(s) into Checkov's graph/report data (useful for SBOM-style inventories or paired platform features), not to flag a specific misconfiguration.

## Non-compliant example
Not applicable — this check cannot fail. Any valid job with (or without) an `image`/`services` key will be recorded and marked passed:

```yaml
build:
  stage: build
  image: node:latest
  services:
    - docker:dind
  script:
    - npm install
    - npm run build
```

## Remediated example
Not applicable in the pass/fail sense, but as a supply-chain hardening practice, pin images to a digest rather than a mutable tag so the recorded inventory reflects an immutable artifact:

```yaml
build:
  stage: build
  image: node:20.11.1@sha256:1b3e2f6b6c... # pinned digest, not :latest
  services:
    - docker:24.0.7-dind@sha256:9f2c4a1e...
  script:
    - npm install
    - npm run build
```

## Remediation steps
1. No remediation is required to satisfy this specific check — it cannot fail.
2. As good practice, still review the inventory of images/services this check surfaces (e.g., in the Checkov JSON/SARIF output) and pin every `image:`/`services:` entry to an immutable digest instead of a floating tag (`latest`, `stable`, a branch name).
3. Source images from a vetted internal registry/mirror where feasible, and enable image scanning on that registry.
4. Pair this inventory with other GitLab CI checks (job permissions, `rules:`/`only:` scoping, secret handling) for a complete supply-chain review of the pipeline.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/gitlab_ci/checks/job/DetectImagesUsage.py)
