# CKV_GHA_6: Found artifact build without evidence of cosign sbom attestation in pipeline
## Severity
**MEDIUM** (score: 4.0/10)

Missing an SBOM attestation reduces supply-chain transparency and makes downstream vulnerability tracking harder, but is primarily a hygiene/traceability gap rather than a directly exploitable weakness.

## Summary
This check fails when a GitHub Actions job builds a software artifact but never generates and attaches a signed SBOM (Software Bill of Materials) attestation via `cosign` (i.e., a `run:` command containing both `cosign` and `sbom`) afterward in that job.

## Applicability
- **Framework:** GitHub Actions workflow YAML
- **Entities:** `jobs` (evaluated at the whole-job level, across all of its steps)

## Why it matters
An SBOM lists every component and dependency that went into a built artifact, which is essential for downstream consumers to answer "am I affected by this newly disclosed CVE?" without having to rebuild or reverse-engineer the artifact themselves. Publishing an artifact without a corresponding, cryptographically-attested SBOM means:
- Consumers and security teams cannot reliably determine the artifact's dependency composition, slowing incident response when a new vulnerability is disclosed in a widely-used library.
- Without a signed attestation binding the SBOM to the specific artifact digest, an unsigned or loosely-associated SBOM document could be swapped out or spoofed, giving a false sense of what's actually running.
- Regulatory and organizational supply-chain security requirements (e.g., U.S. Executive Order 14028-driven SBOM mandates, SLSA provenance requirements) increasingly expect signed SBOM attestations as a baseline control for software delivered into production or to customers.

## How Checkov evaluates this
The check (`CosignSignSBOM`) uses the same build-detection logic as `CKV_GHA_5`: it walks each job's steps and marks `build_found = True` when it encounters a step whose `uses:` matches a known build action or whose `run:` contains a known build command (from the shared `buildactions`/`buildcmds` lookup lists).
- Once a build is detected, it scans subsequent steps' `run:` text for a line containing **both** the substrings `"cosign"` and `"sbom"`.
- If such a step is found, the check **PASSES** immediately.
- If the loop completes with a build detected but no matching `cosign ... sbom` step found afterward, the check **FAILS**.
- If no build step was ever detected, the check **PASSES** (nothing built, nothing to attest).

As with CKV_GHA_5, the SBOM-attestation evidence must appear in a step that comes after the detected build step.

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
      - name: Sign image
        run: cosign sign --yes registry.example.com/app:${{ github.sha }}
```

## Remediated example
```yaml
jobs:
  build-and-push:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      - name: Build image
        run: docker build -t registry.example.com/app:${{ github.sha }} .
      - name: Push image
        run: docker push registry.example.com/app:${{ github.sha }}
      - name: Sign image
        run: cosign sign --yes registry.example.com/app:${{ github.sha }}
      - name: Generate SBOM
        run: syft registry.example.com/app:${{ github.sha }} -o spdx-json > sbom.spdx.json
      - name: Attach and sign SBOM attestation
        run: cosign attest --yes --predicate sbom.spdx.json --type spdxjson registry.example.com/app:${{ github.sha }}
```

## Remediation steps
1. After building and pushing your artifact, generate an SBOM using a tool such as Syft, Trivy, or `docker sbom`.
2. Attach the SBOM to the artifact as a signed attestation using `cosign attest --predicate <sbom-file> --type <spdxjson|cyclonedx>` (the command must contain both `cosign` and `sbom` on the same `run:` line, or otherwise ensure the substrings are present, to satisfy this check).
3. Use keyless OIDC signing (`permissions: id-token: write`) where possible, consistent with your image-signing setup.
4. Ensure the SBOM step runs after the build/push step in the job's step order, matching how Checkov scans steps sequentially.
5. Configure consuming systems (vulnerability scanners, admission controllers) to fetch and verify the SBOM attestation before deployment.
6. Re-run Checkov to confirm the job now contains a step whose `run:` includes both `cosign` and `sbom` after the build.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/github_actions/checks/job/CosignSBOM.py
- Sigstore cosign attestation documentation: https://docs.sigstore.dev/cosign/attest/
