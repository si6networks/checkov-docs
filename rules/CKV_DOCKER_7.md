# CKV_DOCKER_7: Ensure the base image uses a non latest version tag

## Severity
**LOW** (score: 2.0/10)

Using an unpinned `latest` base image tag risks unreviewed/unexpected upstream changes silently reaching builds, but this is primarily a supply-chain and reproducibility hygiene practice rather than a check that closes a direct attack path.

## Summary
This check ensures that every `FROM` instruction in a Dockerfile pins the base image to a specific, immutable version tag rather than relying on the implicit or explicit `:latest` tag (or an untagged reference).

## Applicability
- **IaC framework**: Dockerfile
- **Instruction inspected**: `FROM`
- Applies to every `FROM` line in a Dockerfile, including multi-stage builds.

## Why it matters
`latest` (or an untagged image reference, which defaults to `latest`) is a mutable, moving pointer — the bytes behind that tag can change at any time without your knowledge. This breaks reproducibility and creates several concrete risks:

- **Unreviewed drift**: A rebuild today may pull a completely different image than a rebuild yesterday, silently introducing new OS packages, library versions, or even a compromised upstream image, with no corresponding change in your own source control.
- **Broken rollback**: If a deployment needs to be rolled back to a prior commit, the Dockerfile alone no longer guarantees the same base image is reproduced, since `:latest` at rollback time may not be the same image that was used originally.
- **Supply-chain risk**: An attacker who compromises the upstream `latest` tag (e.g., via a compromised publisher account or CI pipeline) can silently poison every downstream build that references it, with no version bump to signal the change.
- **Untestable changes**: Automated vulnerability scanning and image provenance/attestation become unreliable when the referenced digest keeps changing between scan time and deploy time.

## How Checkov evaluates this
The check (`ReferenceLatestTag`) inspects each `FROM` instruction's value:
1. It first handles multi-stage builds — if the value contains `AS <stage>` (e.g., `FROM golang:1.21 AS builder`), it extracts the actual image reference and records the stage name so later `FROM <stage>` references (referencing a previous build stage rather than a registry image) aren't misflagged.
2. **FAILS** if the base image reference contains no `:` (no tag at all) and is not a previously-defined build stage and is not the special `scratch` image.
3. **FAILS** if the base image reference ends with `:latest`.
4. Otherwise **PASSES**.

## Non-compliant example
```dockerfile
FROM python:latest

COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
CMD ["python", "app.py"]
```

## Remediated example
```dockerfile
FROM python:3.12.4-slim

COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
CMD ["python", "app.py"]
```

## Remediation steps
1. Identify every `FROM` instruction in the Dockerfile (including intermediate build stages that reference an external image).
2. Replace `:latest` or a missing tag with an explicit, specific version tag (e.g., `3.12.4-slim` instead of `latest` or no tag).
3. For maximum reproducibility, consider pinning to an immutable content digest instead of a tag: `FROM python@sha256:<digest>`.
4. Establish a process (e.g., Renovate/Dependabot, or a scheduled pipeline job) to intentionally bump the pinned version on a regular cadence, rather than relying on `latest` to auto-update.
5. Re-scan with Checkov to confirm the `FROM` line now passes; `scratch` and references to earlier build stages in the same Dockerfile are exempted and do not need a tag.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/dockerfile/checks/ReferenceLatestTag.py
