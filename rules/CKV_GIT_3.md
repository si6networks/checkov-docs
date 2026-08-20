# CKV_GIT_3: Ensure GitHub repository has vulnerability alerts enabled
## Severity
**LOW** (score: 2.0/10)

Disabling vulnerability alerts removes visibility into known-vulnerable dependencies, delaying detection of risk rather than directly enabling exploitation.

## Summary
This check ensures that a GitHub repository has Dependabot/GitHub vulnerability alerts (`vulnerability_alerts`) enabled so known-vulnerable dependencies are automatically flagged.

## Applicability
**Checkov framework(s):** `terraform`

Applies to Terraform configurations using the `github` provider, specifically the `github_repository` resource.

## Why it matters
Vulnerability alerts (GitHub's dependency graph + Dependabot alerts feature) automatically notify maintainers when a dependency in the repository has a publicly known CVE. Without this enabled, a team has no automated signal when, say, a transitive npm/pip/Maven package they depend on discloses a critical remote-code-execution or supply-chain vulnerability — the vulnerable dependency can sit in production code indefinitely until someone manually audits it (or until it's exploited). Given that a large share of real-world breaches trace back to known, unpatched vulnerabilities in third-party dependencies rather than novel zero-days, this is a low-cost, high-value control: it's free, automatic, and directly closes the "we didn't know" gap in dependency risk management.

## How Checkov evaluates this
`GithubRepositoryVulnerabilityAlerts` has three branches:
1. If `archived == true` — **PASS** (GitHub disables alerts on archived repos with no way to re-enable them, so this is treated as not applicable rather than a failure).
2. Else, if the repo is private/internal (`private == true` or `visibility` in `["private", "internal"]`): **PASS** only if `vulnerability_alerts` is truthy; otherwise **FAIL**. (GitHub disables alerts by default on private repos, so this must be explicitly turned on.)
3. Else (public repo): **FAIL** only if `vulnerability_alerts == false` explicitly; otherwise **PASS** (GitHub enables alerts by default on public repos).

## Non-compliant example
```hcl
resource "github_repository" "app" {
  name       = "internal-billing-service"
  visibility = "private"
  # vulnerability_alerts not set -> disabled by default on private repos
}
```

## Remediated example
```hcl
resource "github_repository" "app" {
  name                 = "internal-billing-service"
  visibility           = "private"
  vulnerability_alerts = true   # fix: explicitly enable Dependabot vulnerability alerts
}
```

## Remediation steps
1. Add `vulnerability_alerts = true` to every `github_repository` resource, especially private/internal ones (public repos get this by default, but explicit is safer and self-documenting).
2. Ensure the GitHub Dependency graph is enabled for the repository/organization (a prerequisite for vulnerability alerts to have any effect); this is generally on by default for GitHub.com but may need enabling for GitHub Enterprise Server.
3. Pair this with Dependabot security updates (auto-generated PRs that bump the vulnerable dependency) for a closed remediation loop, not just alerting.
4. If a repository is intentionally archived, no action is needed — Checkov treats archived repos as passing since GitHub itself disables alerting on them irreversibly.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/github/RepositoryEnableVulnerabilityAlerts.py)
- [Terraform GitHub provider: github_repository](https://registry.terraform.io/providers/integrations/github/latest/docs/resources/repository)
- [GitHub docs: About Dependabot alerts](https://docs.github.com/en/code-security/dependabot/dependabot-alerts/about-dependabot-alerts)
