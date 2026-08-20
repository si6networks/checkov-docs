# CKV2_GHA_1: Ensure top-level permissions are not set to write-all

## Severity
**HIGH** (score: 7.5/10)

Top-level write-all GITHUB_TOKEN permissions grant every job in the workflow broad write access to the repository (contents, packages, deployments, etc.), significantly widening the blast radius if any step is compromised via a malicious PR or dependency.

## Summary
This check ensures a GitHub Actions workflow's top-level `permissions` key is not set to the shorthand value `write-all`, which grants the workflow's `GITHUB_TOKEN` write access to every scope (contents, packages, issues, pull-requests, etc.) for the duration of the run.

## Applicability
- **IaC framework:** GitHub Actions workflow YAML
- **Entity:** the top-level `permissions` key in a workflow file

This is a graph-based check (Checkov "graph check", defined as JSON) evaluated against the parsed `permissions` attribute of a GitHub Actions workflow.

## Why it matters
The `GITHUB_TOKEN` automatically injected into every workflow run is scoped by the `permissions` block. Setting top-level `permissions: write-all` grants that token full read/write access across all available scopes (repository contents, packages, deployments, issues, pull requests, checks, actions, security-events, etc.) to every job and every step in the workflow — including any third-party action referenced in the workflow, and any code that runs as part of build/test steps. If a dependency, a compromised third-party action, or a maliciously crafted pull request triggers code execution inside the workflow (a well-documented class of GitHub Actions supply-chain attack), the attacker inherits write-all privileges: they could push commits, modify releases, publish packages, or tamper with other workflows. Scoping permissions down to only what each job actually needs drastically limits the blast radius of any single compromised step or action.

## How Checkov evaluates this
The check inspects the `permissions` attribute of the workflow's top-level `permissions` entity. Using a `not_equals` operator, the check **passes** if the value is anything other than the literal string `write-all`, and **fails** if the top-level `permissions` is explicitly (or, per GitHub's resolution rules, effectively) set to `write-all`.

## Non-compliant example
```yaml
name: Lint
on: [pull_request]

permissions: write-all

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run linter
        run: make lint
```

## Remediated example
```yaml
name: Lint
on: [pull_request]

permissions:
  contents: read

jobs:
  lint:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write   # only if the job needs to comment on PRs
    steps:
      - uses: actions/checkout@v4
      - name: Run linter
        run: make lint
```

## Remediation steps
1. Replace the top-level `permissions: write-all` with an explicit, minimal set of scopes — commonly `contents: read` as a safe default for most CI jobs.
2. For jobs that genuinely need write access (e.g., publishing a release, commenting on a PR, pushing to a branch), grant that specific scope (e.g., `contents: write`, `pull-requests: write`) at the **job** level rather than the workflow level, so unrelated jobs stay read-only.
3. For `.github/workflows/lint.yaml` and similar CI-only workflows, `contents: read` is typically sufficient.
4. For `codeql-gh.yml`, CodeQL analysis typically needs `actions: read`, `contents: read`, and `security-events: write` — set these explicitly rather than `write-all`.
5. Test the workflow after tightening permissions — some steps (uploading artifacts, creating check runs) may fail silently if a needed scope was removed; check job logs for `Resource not accessible by integration` errors.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/github_actions/checks/graph_checks/ReadOnlyTopLevelPermissions.json
- GitHub docs: https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication#permissions-for-the-github_token
