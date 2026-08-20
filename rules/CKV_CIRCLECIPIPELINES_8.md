# CKV_CIRCLECIPIPELINES_8: Detecting image usages in circleci pipelines

## Severity
**LOW** (score: 1.0/10)

This check is purely informational (it unconditionally passes and only inventories container images used by executors/jobs), so it closes no attack path on its own.

## Summary
This is an inventory/detection check that records the Docker `image` used by CircleCI executors and jobs; as implemented, it does not actually fail configurations — it always reports a pass and exists to surface image usage data (e.g. for downstream image-vulnerability correlation).

## Applicability
Applies to CircleCI Pipeline configuration files (`.circleci/config.yml`), specifically the `image` field under `executors.*.docker[]` and `jobs.*.docker[]` blocks (the Docker executor images used to run CircleCI jobs).

## Why it matters
Knowing which container images your CI jobs run on is foundational for supply-chain visibility: those images run with access to your source code, secrets, and often deploy credentials, so an unpinned, untrusted, or outdated base image used as a CircleCI executor is itself an attack surface (e.g., a compromised public image publishing malicious content, or a stale image carrying known CVEs in its tooling). Checkov uses checks like this one to extract the `image:` references so that image name/tag/digest data can be cross-referenced with other tooling (image scanning, SBOM generation, policy-as-code around allowed registries) even though this particular check itself does not apply a pass/fail judgment on the image value.

## How Checkov evaluates this
The check (`DetectImageUsage`) is registered against `executors.*.docker[].{image, __startline__, __endline__}` and `jobs.*.docker[].{image, __startline__, __endline__}`, meaning Checkov's JMESPath-based extraction pulls out every `image` value (plus its source line range) from any `docker:` executor list, whether declared under a named `executors:` block or inline under a `jobs:` entry. However, `scan_resource_conf` unconditionally returns `CheckResult.PASSED` for every entity it's given — there is no logic in this check that inspects the image string itself (e.g., no check for `:latest` tags, no digest pinning requirement, no registry allow-list). It functions purely as a data-collection/tagging check within Checkov's internal graph, not a security gate.

## Non-compliant example
Because the check always passes, there is no "non-compliant" configuration for this specific check ID. For illustration, this is a typical image declaration the check extracts data from:
```yaml
version: 2.1

jobs:
  build:
    docker:
      - image: cimg/node:latest
    steps:
      - checkout
      - run: npm ci
```

## Remediated example
Since CKV_CIRCLECIPIPELINES_8 has no failure condition, there is nothing to "fix" for this check to pass. However, as a general best practice the image reference above should still be pinned to a specific, immutable version/digest (this is enforced by other image-hygiene tooling, not this check):
```yaml
version: 2.1

jobs:
  build:
    docker:
      - image: cimg/node:20.11.1
    steps:
      - checkout
      - run: npm ci
```

## Remediation steps
1. No action is required to make this specific check pass — it will report PASSED regardless of the image value.
2. Treat this check's output as inventory data: use it (or a dedicated container-image scanning tool) to confirm every CircleCI executor image is pinned to a specific version/digest rather than a floating tag like `latest`.
3. Periodically audit the collected image list against your organization's approved base-image/registry policy.
4. If your Checkov version or policy tier layers additional rules on top of this data (e.g. a custom policy checking for disallowed registries), address findings from that separate check instead.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/circleci_pipelines/checks/DetectImagesUsage.py
