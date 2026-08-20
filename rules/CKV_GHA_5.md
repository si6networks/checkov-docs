# CKV_GHA_5: Found artifact build without evidence of cosign sign execution in pipeline
## Severity
**MEDIUM** (score: 5.0/10)

Building and publishing artifacts without a cosign signing step weakens supply-chain integrity guarantees (consumers can't verify provenance), but by itself does not directly expose a runtime or credential-theft attack path.

## Summary
This check fails when a GitHub Actions job builds a software artifact (container image, package, binary, etc.) but never runs `cosign sign` anywhere afterward in that same job, meaning the artifact is published without a verifiable cryptographic signature.

## Applicability
**Checkov framework(s):** `github_actions`

- **Framework:** GitHub Actions workflow YAML
- **Entities:** `jobs` (evaluated at the whole-job level, across all of its steps)

## Why it matters
Unsigned build artifacts are a core supply-chain security risk (this is one of the key controls behind frameworks like SLSA and the broader "sign everything you ship" movement popularized by Sigstore/cosign). If a CI pipeline builds a container image or package and publishes it without a signature:
- Downstream consumers (Kubernetes admission controllers, package managers, other pipelines) have no cryptographic way to verify the artifact actually came from this build process and wasn't tampered with in the registry, during transit, or via a compromised mirror.
- An attacker who gains write access to the artifact registry (or intercepts/poisons a distribution channel) can substitute a malicious artifact, and nothing downstream would detect the substitution.
- It undermines any provenance/attestation strategy: signing is the mechanism that binds an artifact's content hash to the identity of the pipeline (via keyless OIDC signing) or a specific signing key, enabling verify-before-deploy policies later in the supply chain.

Requiring evidence of `cosign sign` closes this gap by making artifact signing a mandatory, auditable step of the build itself.

## How Checkov evaluates this
The check (`CosignSignPresent`) walks all steps of every job:
1. It first looks for evidence that a **build** happened, using two static lookup lists imported from `checkov.github_actions.common.build_actions` (`buildactions`) and `checkov.github_actions.common.artifact_build` (`buildcmds`):
   - A step's `uses:` value matching any known build-related action (e.g., Docker/Buildx build actions), or
   - A step's `run:` value containing any known build command substring (e.g., `docker build`, package-build commands).
2. Once a build is detected (`build_found = True`), it continues scanning subsequent steps' `run:` text for the substring `"cosign sign"`.
   - If found, the check **PASSES** immediately.
3. If the loop finishes and a build was found but `cosign sign` was never seen afterward, the check **FAILS**.
4. If no build-related step was ever found in the job, the check **PASSES** (nothing to sign, so nothing to flag).

Note that signing evidence must come *after* the build step is detected in step order — a `cosign sign` step placed before the build step in the same job is not counted.

## Non-compliant example
```yaml
jobs:
  build-and-push:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build image
        run: docker build -t registry.example.com/app:${{ github.sha }} .
      - name: Push image
        run: docker push registry.example.com/app:${{ github.sha }}
```

## Remediated example
```yaml
jobs:
  build-and-push:
    runs-on: ubuntu-latest
    permissions:
      id-token: write   # required for keyless cosign signing
      contents: read
    steps:
      - uses: actions/checkout@v4
      - name: Build image
        run: docker build -t registry.example.com/app:${{ github.sha }} .
      - name: Push image
        run: docker push registry.example.com/app:${{ github.sha }}
      - name: Install cosign
        uses: sigstore/cosign-installer@v3
      - name: Sign image
        run: cosign sign --yes registry.example.com/app:${{ github.sha }}
```

## Remediation steps
1. Install `cosign` in the job (e.g., via `sigstore/cosign-installer`) after the build/push step.
2. Add a `cosign sign` step targeting the exact pushed artifact digest/tag, after the image or package has been pushed to its registry.
3. Prefer keyless signing via OIDC (`cosign sign --yes <image>` with `permissions: id-token: write`) over long-lived private keys stored as secrets, to avoid key-management risk.
4. If using a private key, store it in a secrets manager and reference it via `COSIGN_PASSWORD`/`COSIGN_PRIVATE_KEY` secrets, never checked into the repo.
5. Configure downstream deployment/admission policies (e.g., Kubernetes `cosign` policy-controller or a registry admission webhook) to require and verify this signature before allowing the artifact to run.
6. Re-run Checkov to confirm the job now shows a `cosign sign` step following the build.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/github_actions/checks/job/CosignArtifacts.py
- Sigstore cosign documentation: https://docs.sigstore.dev/cosign/overview/
