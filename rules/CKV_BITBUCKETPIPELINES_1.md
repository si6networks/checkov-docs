# CKV_BITBUCKETPIPELINES_1: Ensure the pipeline image uses a non latest version tag
## Severity
**LOW** (score: 3.0/10)

Using the ':latest' tag for a pipeline image is a supply-chain hygiene and reproducibility concern that can cause unexpected image changes, but does not by itself grant an attacker access or control.

## Summary
This check verifies that Docker images referenced in a Bitbucket Pipelines configuration are pinned to a specific version tag rather than using the mutable `:latest` tag.

## Applicability
**Checkov framework(s):** `bitbucket_pipelines`

- **Bitbucket Pipelines** (`bitbucket-pipelines.yml`): applies to any `step.image` field, whether under `pipelines.default[]` or any custom pipeline/branch/tag pipeline definition.

## Why it matters
The `:latest` tag is a mutable pointer that can point to a different image build at any time, entirely outside your control — whoever maintains the upstream image can push a new `:latest` at will. Relying on it in a CI/CD pipeline creates several problems:
- **Build non-reproducibility**: The exact same pipeline definition can produce different results on different runs, because the underlying image contents silently changed between executions — breaking "build once, verify, deploy" guarantees.
- **Supply-chain risk**: If the upstream image maintainer's account or registry is compromised, a malicious actor can push a backdoored image under the same `:latest` tag, and your pipeline will pull and execute it automatically on the very next run with no code change on your end required.
- **Debugging difficulty**: When a pipeline that previously worked suddenly fails (or, worse, succeeds with different behavior), there's no way to correlate the failure to "the image changed," since the tag reference in your YAML never changed.

Pinning to a specific version tag (or better, a content-addressable digest) ensures the pipeline always runs against a known, reviewed, reproducible image.

## How Checkov evaluates this
The check inspects each `image` field found by the supported entity path expressions (which walk `pipelines.default[]` and any other pipeline step's `image` key, along with a generic top-level fallback). For each `image` value:
- If `image` is a string and it **ends with `:latest`**, the check FAILS.
- If `image` is missing entirely, the result is `UNKNOWN` (not evaluated).
- Otherwise (any other explicit tag, or no tag suffix that resolves to `:latest`), it PASSES.

Note this is a purely string-suffix check on `:latest` — it does not detect the *absence* of a tag (which Docker itself treats as an implicit `:latest`); the sibling check `CKV_CIRCLECIPIPELINES_2`-style hash-pinning logic is not applied here.

## Non-compliant example
```yaml
image: node:latest

pipelines:
  default:
    - step:
        name: Build and Test
        image: node:latest      # <-- mutable, unpinned tag
        script:
          - npm install
          - npm test
```

## Remediated example
```yaml
image: node:18.19.0

pipelines:
  default:
    - step:
        name: Build and Test
        image: node:18.19.0    # <-- pinned to a specific, reproducible version
        script:
          - npm install
          - npm test
```

## Remediation steps
1. Identify every `image:` field in `bitbucket-pipelines.yml` (top-level default image and any per-step overrides).
2. Replace `:latest` (or an implicit untagged reference) with an explicit version tag matching your tested/approved runtime version.
3. For maximum supply-chain assurance, consider pinning to an immutable content digest (`image: node@sha256:<digest>`) instead of a mutable tag, since even a specific version tag can technically be re-pushed by the registry maintainer.
4. Establish a process (e.g. Dependabot/Renovate) to intentionally and visibly bump pinned image versions on a schedule, rather than relying on `:latest` to "auto-update" silently.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/bitbucket_pipelines/checks/latest_image.py
