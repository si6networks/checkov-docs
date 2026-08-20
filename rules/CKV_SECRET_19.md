# CKV_SECRET_19: Hex High Entropy String

## Severity
**LOW** (score: 2.0/10)

This entropy-based detector catches unbranded high-entropy hex secrets (signing keys, session secrets) that are exactly as dangerous as vendor-specific credentials if genuine, but the heuristic nature of the match (versus an exact vendor-format hit) warrants slightly more caution before treating every finding as confirmed critical exposure.

## Summary
This check flags hexadecimal-formatted string literals in scanned files whose Shannon entropy is high enough to statistically resemble a random secret (API key, token, or cryptographic material) rather than ordinary code, config, or a known constant.

## Applicability
**Checkov framework(s):** `secrets`

- **IaC/file type**: `secrets` — Checkov's regex/entropy-based secrets scanner, applied to any scanned file (source code, config files, YAML/JSON, scripts, Dockerfiles, CI pipeline definitions, etc.), not limited to a single IaC resource type. This detector is a generic fallback that runs alongside the vendor-specific pattern detectors (AWS, Slack, Stripe, etc.) to catch secrets that don't match a known provider's format.
- **Entities**: any hex-formatted string token in scanned file content; findings are reported at the file/line level.

## Why it matters
Not every secret has a recognizable vendor prefix — internal API tokens, encryption keys, session secrets, HMAC signing keys, and custom-generated credentials are frequently just raw random hex strings with no distinguishing marker. An entropy-based detector exists precisely to catch this class of secret: a string like a Django `SECRET_KEY`, a JWT signing key, or a randomly generated internal service token would evade every vendor-specific regex but is still exactly as dangerous if leaked — it can allow token forgery, session hijacking, or decryption of protected data, depending on what the key is used for. Because this detector is entropy-based rather than pattern-based, it is the safety net for exactly the secrets an organization is most likely to have "rolled their own" for, which are otherwise invisible to signature-based scanning.

## How Checkov evaluates this
The detector extracts candidate string literals that are composed entirely of hexadecimal characters (`0-9a-fA-F`) and computes their Shannon entropy (a measure of randomness/information density per character). If a hex string's entropy exceeds a calibrated threshold (tuned so that structured/predictable hex — like a short constant, a zero-padded ID, or a UUID with clearly patterned segments — falls below it, while a genuinely random secret of sufficient length falls above it), it is flagged as a FAIL at that file/line. Because this is a statistical heuristic rather than an exact-format match, it can produce more false positives than the vendor-specific detectors (e.g., on certain hashes, checksums, or commit SHAs embedded in code/config) — findings should be reviewed for whether the string is genuinely secret material versus a non-sensitive identifier.

## Non-compliant example
```python
# settings.py
SECRET_KEY = "8f14e45fceea167a5a36dedd4bea2543f2b6a9d8f14e45fceea167a5a36dedd"
```

## Remediated example
```python
# settings.py
import os
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
```

## Remediation steps
1. Determine what the flagged hex string actually is: if it is genuinely secret material (a signing key, API token, encryption key), treat it as compromised and rotate/regenerate it.
2. Remove the literal value from the file and load it from an environment variable or secrets manager at runtime.
3. If the flagged string is a non-secret identifier (a commit hash, checksum, or fixed non-sensitive constant), suppress the specific finding with an inline `checkov:skip=CKV_SECRET_19` comment (with a justification) rather than disabling the check entirely, so real secrets in other locations are still caught.
4. Purge genuinely secret values from git history if they were ever committed/pushed.
5. Consider tuning or reviewing entropy-detector false-positive patterns with your security team if this check produces high noise in a given codebase, rather than disabling it outright.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/common/bridgecrew/integration_features/features/policy_metadata_integration.py)
