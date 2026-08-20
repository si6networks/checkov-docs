# CKV_CIRCLECIPIPELINES_1: Ensure the pipeline image uses a non latest version tag
## Severity
**LOW** (score: 3.0/10)

Referencing a CircleCI job image by the mutable ':latest' tag is a supply-chain hygiene issue that risks unexpected or unreviewed image changes rather than an immediately exploitable vulnerability.

## Summary
This check verifies that Docker executor images referenced in a CircleCI pipeline configuration (`.circleci/config.yml`) are pinned to a specific version tag rather than the mutable `:latest` tag.

## Applicability
**Checkov framework(s):** `circleci_pipelines`

- **CircleCI Pipelines** (`.circleci/config.yml`): applies to `jobs.*.docker[].image` entries (the Docker executor image list for each job).

## Why it matters
The `:latest` tag is a mutable pointer, not a fixed version — the image it resolves to can change at any time without any corresponding change to your pipeline configuration. In a CI context this creates real risk:
- **Build non-reproducibility**: Two runs of the identical `config.yml` can execute against two different underlying images, so a "green" build today provides no guarantee the same code will build/test identically tomorrow.
- **Supply-chain compromise vector**: If the maintainer of the upstream `:latest` image (or the registry account behind it) is compromised, a malicious image can be pushed and your CI will pull and execute it automatically the very next run — with no diff in your repo to review or flag the change.
- **Silent breakage**: An upstream image update (e.g. a new OS package version, a changed default shell, a removed tool) can break your pipeline in ways that are hard to trace back to "the image changed," since your config file shows no change.

Pinning executor images to a specific, tested version tag ensures builds run against a known, reviewed environment every time.

## How Checkov evaluates this
For each Docker executor entry (an `image` field under `jobs.<job>.docker[]`):
- If `image` is a string and it **ends with `:latest`**, the check FAILS.
- If `image` is missing or not a dict-shaped config entry, the check PASSES (not applicable / nothing to flag).
- Otherwise (any explicit non-`latest` tag), it PASSES.

This is a simple string-suffix match on `:latest` — it does not detect the absence of any tag at all (which Docker treats as an implicit `:latest`) and does not verify the tag resolves to an immutable digest (see CKV_CIRCLECIPIPELINES_2 for the digest-pinning check).

## Non-compliant example
```yaml
version: 2.1

jobs:
  build:
    docker:
      - image: cimg/node:latest    # <-- mutable, unpinned tag
    steps:
      - checkout
      - run: npm install
      - run: npm test
```

## Remediated example
```yaml
version: 2.1

jobs:
  build:
    docker:
      - image: cimg/node:20.11.1   # <-- pinned to a specific, reproducible version
    steps:
      - checkout
      - run: npm install
      - run: npm test
```

## Remediation steps
1. Locate every `image:` entry under each job's `docker:` executor list in `.circleci/config.yml`.
2. Replace `:latest` with an explicit version tag that matches your tested runtime (e.g. `cimg/node:20.11.1` instead of `cimg/node:latest`).
3. For stronger supply-chain guarantees, pin to an immutable content digest (`image: cimg/node@sha256:<digest>`) rather than a mutable version tag — see CKV_CIRCLECIPIPELINES_2.
4. Set up a scheduled dependency-update process (e.g. Renovate/Dependabot config for CircleCI images) so pinned versions are bumped deliberately and reviewably, instead of relying on `:latest` for implicit updates.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/circleci_pipelines/checks/latest_image.py
