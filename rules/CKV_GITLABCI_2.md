# CKV_GITLABCI_2: Avoid creating rules that generate double pipelines
## Severity
**LOW** (score: 2.5/10)

Rules that can trigger duplicate pipelines mainly waste CI resources and cause confusing status results rather than expose a direct security weakness.

## Summary
This check flags GitLab CI job `rules` blocks that would trigger the same job for both a `merge_request_event` and a `push` event on the same underlying change, causing duplicate ("double") pipeline runs.

## Applicability
Applies to GitLab CI pipeline configuration (`gitlab_ci` IaC type, check type `jobs`), evaluated against a job's `rules` array (entity `*.rules`).

## Why it matters
While framed here as a pipeline-reliability/cost issue rather than a direct vulnerability, duplicate pipeline triggering has real operational and security-adjacent consequences: doubled CI runs waste compute/runner capacity (a resource-exhaustion / cost-abuse vector, and in shared-runner environments can starve other jobs), and — more importantly — can cause confusing, inconsistent results where a merge-request pipeline and a branch-push pipeline for the *same commit* run independently and potentially report different status or deploy the same change twice concurrently (e.g., double-triggering a deployment job, or race conditions in jobs that aren't idempotent). This is a classic GitLab CI misconfiguration: enabling both `merge_request_event` and `push` triggers for the same source branch pattern without excluding one from the other.

## How Checkov evaluates this
The check looks at each entry in the job's `rules` list. For every rule dict containing an `if` key, it checks whether the rule's condition string starts with one of two known pipeline-source conditions: `$CI_PIPELINE_SOURCE == "merge_request_event"` or `$CI_PIPELINE_SOURCE == "push"`. It counts how many rules match either of these conditions; if more than one rule (i.e., both conditions, or the same condition twice) is present, the check FAILS, since this combination is what causes the same underlying commit to spawn two pipelines. If at most one such condition is present, the check PASSES.

## Non-compliant example
```yaml
test:
  stage: test
  script:
    - run-tests.sh
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '$CI_PIPELINE_SOURCE == "push"'
```

## Remediated example
```yaml
test:
  stage: test
  script:
    - run-tests.sh
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '$CI_PIPELINE_SOURCE == "push" && $CI_COMMIT_BRANCH == "main"'
      when: never
    - if: '$CI_COMMIT_BRANCH'
```
(Fix: exclude the `push` case whenever a merge request pipeline for the same change will already run — e.g., only allow the `push` trigger for branches that are never the source of an open merge request, such as protected/default branches, or explicitly set `when: never` for the redundant combination.)

## Remediation steps
1. Identify jobs whose `rules` allow triggering on both `$CI_PIPELINE_SOURCE == "merge_request_event"` and `$CI_PIPELINE_SOURCE == "push"` for the same branches.
2. Restructure the rules so only one event source triggers the pipeline for a given branch — commonly: run on `merge_request_event` for feature branches, and reserve `push` triggers for branches that don't have open merge requests (e.g., default branch, tags, or direct pushes to protected branches).
3. Use GitLab's recommended workflow rules pattern (`workflow:rules` at the pipeline level) to centrally prevent duplicate pipelines rather than repeating logic in every job.
4. Add explicit `when: never` entries for the redundant combination rather than relying on ordering/implicit exclusion, to make the intent clear to future maintainers.
5. After changing rules, verify in the GitLab pipeline UI that a single merge request push produces exactly one pipeline, not two.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/gitlab_ci/checks/job/AvoidDoublePipelines.py)
- [GitLab Docs: Avoid duplicate pipelines](https://docs.gitlab.com/ee/ci/jobs/job_rules.html#avoid-duplicate-pipelines)
