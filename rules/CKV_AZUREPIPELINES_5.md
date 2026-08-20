# CKV_AZUREPIPELINES_5: Detecting image usages in azure pipelines workflows

## Severity
**LOW** (score: 3.0/10)

This check only detects and inventories container image usage within pipeline definitions for visibility purposes; it does not itself identify a specific insecure configuration or exploitable weakness.

## Summary
This is an informational/inventory check, not a pass/fail security gate — it exists so Checkov's supply-chain graph can enumerate every container image reference used across a pipeline's jobs, for use by other checks and by SCA/inventory tooling, and it always reports a passing result itself.

## Applicability
- **Azure Pipelines** YAML pipeline definitions — applies to `jobs[]`, `stages[].jobs[]`, and any `container[]` entries found anywhere in the document (the `*.container[]` wildcard entity), i.e., it walks the whole pipeline looking for container image references.

## Why it matters
This check doesn't itself flag a security condition — its `scan_conf` unconditionally returns `CheckResult.PASSED` for every entity it's given. Its purpose is enumeration: by matching on `jobs[]`, `stages[].jobs[]`, and `*.container[]`, Checkov's scan surfaces every container image reference present in the pipeline (regardless of tag/digest hygiene) so that this information is available in scan output/graph data for downstream use — e.g., correlating which images a pipeline pulls, feeding image inventories, or supporting other checks (such as CKV_AZUREPIPELINES_1 and CKV_AZUREPIPELINES_2, which evaluate the *quality* of those same references) with a consistent way of locating them. If you see this ID in a Checkov report, it is not indicating a vulnerability by itself — it is there to record what images were found.

## How Checkov evaluates this
The `scan_conf` method for this check contains no conditional logic at all — it takes whatever `conf` (the matched `jobs`, `stages[].jobs[]`, or `container[]` block) is passed in and immediately returns `(CheckResult.PASSED, conf)`. There is no failing condition defined anywhere in the check.

## Non-compliant example
Not applicable — this check cannot fail. Any pipeline job or container reference will register a PASSED result for this check ID.

## Remediated example
Not applicable — no remediation is needed for this check specifically. If you are trying to secure container image references themselves, see CKV_AZUREPIPELINES_1 (non-`latest` tag) and CKV_AZUREPIPELINES_2 (digest pinning).

## Remediation steps
1. No action is required for this check ID on its own — it will not appear as a failed finding.
2. If you're reviewing Checkov output and see `CKV_AZUREPIPELINES_5` listed, treat it as an inventory/detection record of a container image reference rather than a defect to fix.
3. Use its presence (and the associated resource/file location in your Checkov output) to build or verify an inventory of container images consumed by your Azure Pipelines, which can feed into image-vulnerability scanning or supply-chain review processes external to Checkov.
4. Focus remediation effort on the related quality checks (CKV_AZUREPIPELINES_1, CKV_AZUREPIPELINES_2) for the images this check surfaces.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/azure_pipelines/checks/job/DetectImagesUsage.py
