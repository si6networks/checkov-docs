# CKV_CIRCLECIPIPELINES_3: Ensure mutable development orbs are not used.

## Severity
**MEDIUM** (score: 6.0/10)

Pinning to a mutable @dev orb tag breaks the immutability guarantee of the CI supply chain, letting a compromised or careless orb publisher push new code that pipelines execute automatically with access to job secrets, but exploitation requires a separate compromise of the orb source.

## Summary
This check fails a CircleCI pipeline configuration if it references an orb tagged with the `@dev` volatility label, which points at a mutable, in-development release rather than a pinned, immutable version.

## Applicability
**Checkov framework(s):** `circleci_pipelines`

Applies to CircleCI Pipeline configuration files (`.circleci/config.yml`), specifically the top-level `orbs` block, where each entry is a string of the form `namespace/orb-name@version-or-tag`.

## Why it matters
CircleCI orbs are reusable packages of YAML that can execute arbitrary commands, install tooling, and access job-level secrets/environment variables during CI runs. An orb reference tagged `@dev:<label>` (development orb) is explicitly mutable — the orb's maintainer can push new content to that same tag at any time without changing the reference in your config. This breaks the supply-chain guarantee that a given orb reference always resolves to the same, previously-reviewed code. If an attacker compromises the orb publisher's account, or if the orb author unintentionally publishes broken/malicious content to the dev tag, every pipeline pinned to `@dev` picks up the new code on its next run automatically — without a corresponding change to your repository that could be reviewed or diffed. This is a textbook CI/CD software supply-chain risk (similar in spirit to floating Docker tags or unpinned GitHub Actions).

## How Checkov evaluates this
The check (`PreventDevelopmentOrbs`) iterates over every value in the parsed `orbs` mapping. For each orb reference that is a string, it checks whether the substring `"@dev"` appears anywhere in it. If any orb reference contains `@dev`, the check returns `FAILED` for the whole `orbs` block (the implementation notes it cannot currently attribute the failure to one specific orb entry due to how the JMESPath-based entity extraction works — one FAILED/PASSED result covers the entire array). If no orb reference contains `@dev`, the check returns `PASSED`.

## Non-compliant example
```yaml
version: 2.1

orbs:
  node: circleci/node@dev:alpha
  aws-cli: circleci/aws-cli@3.1.4

jobs:
  build:
    executor: node/default
    steps:
      - checkout
      - node/install-packages
```

## Remediated example
```yaml
version: 2.1

orbs:
  node: circleci/node@5.1.0
  aws-cli: circleci/aws-cli@3.1.4

jobs:
  build:
    executor: node/default
    steps:
      - checkout
      - node/install-packages
```

## Remediation steps
1. Identify every orb entry under the `orbs:` key that has a version string containing `@dev` (e.g. `@dev:alpha`, `@dev:my-branch`).
2. Replace the `@dev:<tag>` reference with a specific, published semantic version (e.g. `@5.1.0`) or a "stable" release tag if the orb publisher offers one.
3. If you need to test unreleased orb functionality, do so in a scratch/experimental project, not in pipelines that build, test, or deploy production artifacts.
4. Consider enabling CircleCI's "Orb Security Settings" to restrict which orbs (and which volatility levels) are allowed to run in your organization.
5. Re-run `checkov -d .circleci` (or your CI security scan) to confirm the finding clears.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/circleci_pipelines/checks/prevent_development_orbs.py
