# CKV_BITBUCKET_1: Merge requests should require at least 2 approvals
## Severity
**MEDIUM** (score: 5.0/10)

Requiring fewer than two approvals on merge requests weakens the code-review control that catches malicious or erroneous changes before they reach protected branches, a supply-chain integrity risk rather than a direct technical vulnerability.

## Summary
This check verifies that a Bitbucket repository's branch restrictions configuration enforces a minimum of 2 required reviewer approvals before a pull request can be merged.

## Applicability
**Checkov framework(s):** `bitbucket_configuration`

- **Bitbucket configuration** (`bitbucket_configuration` — Checkov's scan of live Bitbucket repository settings/branch-restrictions API responses, not a `bitbucket-pipelines.yml` file): applies to the branch restrictions resource as a whole (`supported_entities = ("*",)`).

## Why it matters
Merge/pull-request approval requirements are a core supply-chain and code-quality control. If a repository does not require at least two independent approvals before merging:
- A single compromised or malicious developer account (or a developer who is themselves compromised via a phished credential) can merge arbitrary code — including a backdoor, credential exfiltration logic, or a supply-chain-poisoning dependency bump — directly into a protected branch with no second set of eyes.
- Human error is far more likely to reach production undetected: a single reviewer can miss a subtle bug, security flaw, or unintended change that a second independent reviewer might catch.
- Compliance frameworks (SOC 2, ISO 27001, PCI-DSS change management controls) commonly require documented, multi-person review of changes before they reach production-relevant branches — a single-approval or no-approval policy fails this control outright.

Requiring 2+ approvals enforces a "four eyes" principle, meaningfully raising the bar for both malicious insider action and accidental defects reaching protected code.

## How Checkov evaluates this
The check validates the scanned configuration against a `branch_restrictions` schema. If the configuration validates against that schema, it iterates the `values` list, looking for an entry where:
- `kind == "require_approvals_to_merge"`

For that entry, if its `value` (the configured number of required approvals) is **>= 2**, the check PASSES. If no such restriction entry exists, or its value is less than 2 (e.g. 0 or 1), the check FAILS. If the configuration doesn't match the expected schema at all, the check returns `None` (not applicable/not evaluated).

## Non-compliant example
```json
{
  "values": [
    {
      "kind": "require_approvals_to_merge",
      "value": 1
    },
    {
      "kind": "push",
      "pattern": "main",
      "value": null
    }
  ]
}
```

## Remediated example
```json
{
  "values": [
    {
      "kind": "require_approvals_to_merge",
      "value": 2
    },
    {
      "kind": "push",
      "pattern": "main",
      "value": null
    }
  ]
}
```

## Remediation steps
1. In the Bitbucket repository settings, navigate to **Repository settings > Branch restrictions** (or **Branch permissions**, depending on Bitbucket Cloud/Server version).
2. Add or edit the "Require approvals for merging checks to pass" restriction, setting the minimum number of approvals to **2 or greater**, applied to your protected branches (e.g. `main`, `master`, release branches).
3. If managing branch restrictions as code (e.g. via Terraform's `bitbucket` provider or the Bitbucket REST API), set the corresponding `require_approvals_to_merge` restriction value to `2` (or higher).
4. Combine with "prevent self-approval" and "require passing builds" restrictions for a more complete merge-protection policy.
5. Communicate the change to the team, since it may slow down merges for solo-maintained repos — consider whether a smaller team needs an alternate compensating control (e.g. mandatory CI checks) if 2 reviewers isn't practical.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/bitbucket/checks/merge_requests_approvals.py
