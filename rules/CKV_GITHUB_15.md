# CKV_GITHUB_15: Ensure inactive branches are reviewed and removed periodically
## Severity
**LOW** (score: 3.0/10)

Failing to periodically review and remove inactive branches is primarily a repository-hygiene issue that can accumulate stale, unreviewed code but rarely constitutes a directly exploitable attack path on its own.

## Summary
This check fails when a repository branch's last commit is older than 60 days, flagging stale branches that should be reviewed and cleaned up.

## Applicability
- **Framework:** GitHub repository configuration (`github_configuration`)
- **Entities:** `*` — evaluated per-branch against branch/commit metadata (`commit/commit/author`, specifically the commit author's `date`), validated against Checkov's internal `branch` schema

## Why it matters
Long-lived, inactive branches accumulate in most active repositories and pose several concrete risks:
- **Stale/vulnerable code paths:** an old branch may contain outdated dependencies with since-disclosed vulnerabilities, or may be based on a version of the codebase that predates important security fixes. If such a branch is later revived, merged, or even just deployed from accidentally, it can reintroduce fixed vulnerabilities.
- **Attack surface and confusion:** inactive branches sometimes still have CI/CD triggers wired to them (e.g., a forgotten deployment workflow), or webhooks/integrations that assume they're maintained, creating unmonitored automation paths.
- **Secret/credential exposure:** old branches occasionally contain credentials or internal details that were since scrubbed from the main branch's history but persist unnoticed in an abandoned branch.
- **Operational hygiene:** stale branches make it harder for maintainers to reason about what's active, complicate branch protection rule management, and can accumulate to the point of causing GitHub API/tooling performance issues.

Regularly identifying and pruning inactive branches keeps the repository's true attack surface aligned with what's actually reviewed and maintained.

## How Checkov evaluates this
The check (`GithubDisallowInactiveBranch60Days`) validates the scanned configuration against an internal `branch` JSON schema, then uses a JSONPath expression to locate the `commit.commit.author` field's `date` value for the branch. It parses that ISO 8601 timestamp (`%Y-%m-%dT%H:%M:%SZ`) and compares it to the current date minus 60 days:
- If the branch's last commit date is **earlier than** 60 days ago, the check **FAILS**.
- If the last commit is within the last 60 days, the check **PASSES**.
- If the schema doesn't validate, no matching data is found, or the date is missing/empty, the result is `UNKNOWN`.

## Non-compliant example
Branch metadata (as retrieved from the GitHub API) showing a stale last commit:
```json
{
  "name": "feature/old-experiment",
  "commit": {
    "commit": {
      "author": {
        "name": "jdoe",
        "date": "2025-11-01T10:00:00Z"
      }
    }
  }
}
```
(More than 60 days before the scan date.)

## Remediated example
Either the branch has recent activity, or — more commonly — it has been deleted/merged so it no longer appears in the scan:
```json
{
  "name": "feature/active-work",
  "commit": {
    "commit": {
      "author": {
        "name": "jdoe",
        "date": "2026-08-10T10:00:00Z"
      }
    }
  }
}
```

## Remediation steps
1. Run a periodic branch audit (manually via `git branch -r --sort=-committerdate` or via GitHub's UI "Branches" view, or automatically via a scheduled workflow) to list branches with no commits in the last 60 days.
2. For each stale branch, confirm with the author/team whether it is still needed.
3. Merge or rebase any branch that still contains valuable, unmerged work; delete branches that are abandoned, already merged, or superseded.
4. Consider enabling GitHub's **"Automatically delete head branches"** repository setting so merged PR branches are cleaned up automatically, reducing the population of stale branches going forward.
5. For branches that must persist long-term for legitimate reasons (e.g., long-running release branches), document the exception rather than treating every finding as an automatic deletion candidate.
6. Re-run Checkov's GitHub scan to confirm the branch either has recent activity or no longer exists.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/github/checks/disallow_inactive_branch_60days.py
- GitHub documentation on automatically deleting head branches: https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/managing-the-automatic-deletion-of-branches
