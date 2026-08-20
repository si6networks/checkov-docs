# CKV_CIRCLECIPIPELINES_2: Ensure the pipeline image version is referenced via hash not arbitrary tag
## Severity
**MEDIUM** (score: 4.5/10)

Pinning a CircleCI job image by tag instead of an immutable digest allows the underlying image to be silently replaced (tag mutation), a supply-chain integrity weakness that can be used to smuggle malicious content into the build.

## Summary
This check verifies that Docker executor images in a CircleCI pipeline configuration are referenced by an immutable content digest (`@sha256:...`) rather than by a mutable tag name.

## Applicability
- **CircleCI Pipelines** (`.circleci/config.yml`): applies to `jobs.*.docker[].image` entries (the Docker executor image list for each job).

## Why it matters
Even a specific, non-`latest` version tag (e.g. `cimg/node:20.11.1`) is not truly immutable — a tag is just a label the registry maintainer can re-point to a different image manifest at any time, whether by accident or through a compromised publishing pipeline. Only a content digest (`sha256` hash of the image manifest) is guaranteed to always resolve to exactly the same bytes. Relying on tags alone means:
- **Reproducibility gap**: The same tag string can silently resolve to different image content over time, even without an obvious signal like a `:latest` label, defeating the goal of fully reproducible CI builds.
- **Supply-chain integrity**: If an attacker compromises the image registry or the publisher's account, they can re-push a malicious image under an *existing, already-referenced* tag (a "tag mutation" attack), and every pipeline referencing that tag will pull the compromised image on its next run — with zero change required to your `config.yml`.
- **Digest pinning is the strongest practical control** against this class of attack, since a digest reference cryptographically guarantees you always get the exact image content that was reviewed and approved when the digest was first pinned.

## How Checkov evaluates this
For each Docker executor `image` entry:
- If `image` contains an `@` character (i.e., a digest reference like `image@sha256:<hash>`), the check PASSES.
- Else if the image string contains the substring `"latest"`, the result is `UNKNOWN` rather than FAILED — this is intentional, since `CKV_CIRCLECIPIPELINES_1` already produces a more specific, actionable failure for the `:latest` case, and this check avoids duplicating that finding.
- Otherwise (a tag is present but it's not `latest` and there's no digest), the check FAILS — because a tag alone, even a "specific-looking" one, is not an immutable reference.
- If `image` is missing or the config entry isn't a dict, the check PASSES (not applicable).

## Non-compliant example
```yaml
version: 2.1

jobs:
  build:
    docker:
      - image: cimg/node:20.11.1    # <-- specific tag, but still mutable
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
      - image: cimg/node@sha256:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b
        # <-- pinned to an immutable content digest
    steps:
      - checkout
      - run: npm install
      - run: npm test
```

## Remediation steps
1. Resolve the digest for your currently-used image tag: `docker pull cimg/node:20.11.1 && docker inspect --format='{{index .RepoDigests 0}}' cimg/node:20.11.1`.
2. Replace the tag reference in `.circleci/config.yml` with the `image@sha256:<digest>` form.
3. Keep a comment noting the human-readable tag/version the digest corresponds to, since digests alone are not self-describing (e.g. `# cimg/node:20.11.1`).
4. Establish a deliberate process (e.g. a scheduled job or Renovate/Dependabot digest-pinning support) to re-resolve and bump the digest when you intentionally want to move to a newer image version — digest pinning trades convenience for reproducibility, so updates must now be explicit.
5. This check will report `UNKNOWN` (not `FAILED`) for images still tagged `:latest` — remediate those via CKV_CIRCLECIPIPELINES_1 first (pin to a real version), then apply this check's digest-pinning guidance.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/circleci_pipelines/checks/image_version_not_hash.py
