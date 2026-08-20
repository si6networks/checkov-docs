# CKV_CIRCLECIPIPELINES_4: Ensure unversioned volatile orbs are not used.

## Severity
**MEDIUM** (score: 6.0/10)

Referencing an unversioned volatile orb tag has the same supply-chain-integrity weakness as a mutable dev orb — code executed in the pipeline (with secret access) can change without a corresponding, reviewable change to the repository.

## Summary
This check fails a CircleCI pipeline configuration if it references an orb tagged `@volatile`, meaning the orb's publisher may push changes to that reference at any time without a corresponding, reviewable config change.

## Applicability
Applies to CircleCI Pipeline configuration files (`.circleci/config.yml`), specifically the top-level `orbs` block, where each entry is a string of the form `namespace/orb-name@version-or-tag`.

## Why it matters
CircleCI's `@volatile` tag is explicitly designed to always resolve to the *latest* published version of an orb, rather than a fixed release. This is convenient for orb authors during rapid iteration, but it means the actual code your pipeline executes can change between runs with no diff in your repository. Orbs run with access to job context, secrets, and environment variables, so an unreviewed change to volatile orb content is effectively an unreviewed change to your CI/CD execution path — a classic software-supply-chain weak link. If the orb is compromised, or a bad release is volatile-tagged, every consumer pinned to `@volatile` is immediately exposed on their next build, with no ability to roll back by pinning to an older, known-good commit/tag in your own repo.

## How Checkov evaluates this
The check (`PreventVolatileOrbs`) iterates over every string value in the parsed `orbs` mapping and looks for the literal substring `"@volitile"` (note: the check's source code contains this typo, matching literally `@volitile`, not the standard `@volatile` spelling). If a match is found in any orb reference, the whole `orbs` block is reported as `FAILED` (as with CKV_CIRCLECIPIPELINES_3, the implementation currently can't attribute the failure to a single specific orb line). Otherwise it returns `PASSED`.

> Note: Because of the exact string match implemented in the check, verify against your installed Checkov version's actual matching behavior (`@volitile` vs `@volatile`) — do not assume the check catches every real-world `@volatile` tag if the shipped code differs from what's captured here.

## Non-compliant example
```yaml
version: 2.1

orbs:
  slack: circleci/slack@volatile
  aws-cli: circleci/aws-cli@3.1.4

jobs:
  notify:
    docker:
      - image: cimg/base:current
    steps:
      - slack/notify:
          event: fail
          template: basic_fail_1
```

## Remediated example
```yaml
version: 2.1

orbs:
  slack: circleci/slack@4.13.3
  aws-cli: circleci/aws-cli@3.1.4

jobs:
  notify:
    docker:
      - image: cimg/base:current
    steps:
      - slack/notify:
          event: fail
          template: basic_fail_1
```

## Remediation steps
1. Search `.circleci/config.yml` for any orb version pinned to `@volatile`.
2. Pin the orb to an explicit, immutable semantic version (e.g. `@4.13.3`) published by the vendor.
3. Track orb version upgrades deliberately (e.g. via Dependabot/Renovate or a scheduled review) instead of relying on `@volatile` to auto-update.
4. Use CircleCI's Orb Security Settings at the org level to disallow volatile/dev orb tags org-wide, preventing this from being reintroduced.
5. Re-scan the config to confirm the finding is resolved.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/circleci_pipelines/checks/prevent_volatile_orbs.py
