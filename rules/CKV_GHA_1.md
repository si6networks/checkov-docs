# CKV_GHA_1: Ensure ACTIONS_ALLOW_UNSECURE_COMMANDS isn't true on environment variables
## Severity
**HIGH** (score: 8.0/10)

Setting `ACTIONS_ALLOW_UNSECURE_COMMANDS` to true re-enables a workflow-commands feature that was disabled upstream specifically because it let untrusted step output inject arbitrary environment variables and execute unintended commands in the runner context.

## Summary
This check fails when a GitHub Actions workflow job or step sets the environment variable `ACTIONS_ALLOW_UNSECURE_COMMANDS` to a truthy value, which re-enables a deprecated and dangerous workflow-command mechanism.

## Applicability
**Checkov framework(s):** `github_actions`

- **Framework:** GitHub Actions workflow YAML
- **Entities:** `jobs` (job-level `env` block) and `jobs.*.steps[]` (step-level `env` block)

The check evaluates any job or step configuration block that carries an `env` map.

## Why it matters
GitHub Actions historically allowed workflow steps to set outputs, environment variables, and other state by writing specially-formatted strings to stdout (e.g., `::set-env name=FOO::bar`, `::add-path::...`), called "workflow commands." In 2020, GitHub disabled the most dangerous of these (`set-env` and `add-path`) by default after a security researcher demonstrated that **any script or action that echoes untrusted, attacker-controlled input to stdout could inject arbitrary environment variables or PATH entries into the runner**. For example, a compromised or malicious dependency printing a crafted string could set `LD_PRELOAD`, override tool paths, or inject secrets-adjacent environment variables into subsequent steps.

Setting `ACTIONS_ALLOW_UNSECURE_COMMANDS: true` deliberately re-enables this legacy, vulnerable command-processing behavior. Combined with any step in the workflow that echoes untrusted content (issue titles, PR bodies, branch names, third-party action logs, etc.), this reopens a known environment-variable/PATH-injection vector that can lead to arbitrary code execution in later steps, including steps that have access to repository secrets.

## How Checkov evaluates this
The check (`AllowUnsecureCommandsOnJob`) inspects the `env` mapping of a job or step:
- If the configuration isn't a dict, the result is `UNKNOWN`.
- If there is no `env` key, or `env` is empty, the check **PASSES**.
- If `env` is present but is not itself a dict, the result is `UNKNOWN`.
- If `env.ACTIONS_ALLOW_UNSECURE_COMMANDS` evaluates truthy (e.g., `true`, `"true"`), the check **FAILS**.
- Otherwise it **PASSES**.

## Non-compliant example
```yaml
name: CI
on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    env:
      ACTIONS_ALLOW_UNSECURE_COMMANDS: true
    steps:
      - uses: actions/checkout@v4
      - run: ./build.sh
```

## Remediated example
```yaml
name: CI
on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: ./build.sh
```

## Remediation steps
1. Remove `ACTIONS_ALLOW_UNSECURE_COMMANDS` from job-level and step-level `env` blocks entirely — do not just set it to `false`; simply not declaring it preserves the secure default.
2. If a legacy action in your workflow depends on `set-env`/`add-path` workflow commands, upgrade it to a version that uses the modern `GITHUB_ENV` / `GITHUB_PATH` files instead (`echo "NAME=value" >> "$GITHUB_ENV"`).
3. Audit any step that writes third-party or user-controlled content to stdout — treat it as untrusted regardless of this flag, since other injection vectors (e.g., unsanitized `run:` blocks) can still exist.
4. Re-run Checkov to confirm the flag is absent or falsy.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/github_actions/checks/job/AllowUnsecureCommandsOnJob.py
- GitHub's deprecation announcement for `set-env`/`add-path`: https://github.blog/changelog/2020-10-01-github-actions-deprecating-set-env-and-add-path-commands/
