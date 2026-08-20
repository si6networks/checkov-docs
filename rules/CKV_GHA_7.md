# CKV_GHA_7: GitHub Actions workflow_dispatch inputs MUST be empty
## Severity
**HIGH** (score: 7.0/10)

A non-empty `workflow_dispatch` input schema lets a user-supplied parameter influence the build beyond the entry point and source location, undermining build provenance guarantees and opening a path for parameter-driven tampering with build output.

## Summary
This check fails when a workflow's `on.workflow_dispatch` trigger declares any `inputs`, on the theory that build output must not be influenced by arbitrary user-supplied parameters beyond the build entry point and top-level source location.

## Applicability
**Checkov framework(s):** `github_actions`

- **Framework:** GitHub Actions workflow YAML
- **Entities:** `on` (the workflow trigger configuration block)

## Why it matters
`workflow_dispatch` lets any user with the right repository permission manually trigger a workflow run from the UI/API and supply free-form `inputs`. If those inputs are then consumed inside the workflow (e.g., interpolated into a `run:` command, used to select a branch/ref to build, or passed as build flags), several risks follow:
- **Build integrity / provenance:** this check encodes a SLSA-style provenance requirement — that a build's output is fully determined by its source and entry point, not by arbitrary operator-supplied parameters. If inputs can change what gets built or how, two runs claiming to build "the same thing" may not actually produce the same, reproducible artifact, undermining trust in generated provenance/attestations.
- **Injection risk:** free-form `workflow_dispatch` inputs are user-controlled strings, and if interpolated unsafely into a `run:` block, they create the same class of script-injection vulnerability described in CKV_GHA_2 — except here the "attacker" need only be someone with dispatch permission, and the input field is explicitly designed to accept arbitrary text.
- **Privilege/parameter abuse:** inputs are sometimes (mis)used to let a caller select a deployment target, toggle safety checks, or pass credentials-adjacent values, effectively turning a convenience feature into an unreviewed control-plane lever.

## How Checkov evaluates this
The check (`EmptyWorkflowDispatch`) inspects the `on:` block's configuration:
- If `on:` is a YAML list (e.g., `on: [push, workflow_dispatch]`) and it contains the bare string `"workflow_dispatch"`, the check **PASSES** (a bare trigger name has no inputs by construction). If the list doesn't contain it, the result is `UNKNOWN`.
- If `on:` is a single string equal to `"workflow_dispatch"`, it **PASSES**; any other string is `UNKNOWN`.
- Otherwise (the common case — `on:` is a mapping), it looks up `conf["workflow_dispatch"]`. If that value is itself a dict, it reads its `inputs` sub-key. If `inputs` is present and non-empty, the check **FAILS**. Otherwise it **PASSES**.

In short: `workflow_dispatch:` with no `inputs:` key (or an empty one) passes; `workflow_dispatch:` with any declared `inputs:` fails.

## Non-compliant example
```yaml
on:
  workflow_dispatch:
    inputs:
      environment:
        description: "Target environment"
        required: true
        type: string
      version:
        description: "Version to deploy"
        required: false
        type: string

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: ./deploy.sh "${{ github.event.inputs.environment }}" "${{ github.event.inputs.version }}"
```

## Remediated example
```yaml
on:
  workflow_dispatch: {}

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: ./deploy.sh "$(cat environment.txt)" "$(git rev-parse HEAD)"
```

## Remediation steps
1. Remove any `inputs:` block under `workflow_dispatch:` — the trigger can still be manually dispatched, it simply won't accept free-form parameters.
2. If your workflow genuinely needs configurable behavior, drive it from values checked into the repository (config files, tags, branch naming conventions) rather than operator-supplied strings at dispatch time, so the build output remains a pure function of the source ref.
3. If you must accept operator input for legitimate operational reasons (e.g., choosing a deployment environment from a fixed, validated set), consider a `choice`-typed input, keep the impact strictly limited to non-code-execution decisions, and never interpolate it directly into a `run:` shell block — pass it via `env:` instead (see CKV_GHA_2's remediation).
4. Re-evaluate whether this level of strictness fits your threat model — this check reflects a supply-chain/provenance best practice (SLSA-aligned), and some teams may accept scoped, well-audited inputs as an intentional exception.
5. Re-run Checkov to confirm `workflow_dispatch` has no `inputs` key.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/github_actions/checks/job/EmptyWorkflowDispatch.py
- GitHub Actions `workflow_dispatch` event documentation: https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#workflow_dispatch
- SLSA build provenance requirements: https://slsa.dev/spec/v1.0/requirements
