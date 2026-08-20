# CKV_DOCKER_5: Ensure update instructions are not use alone in the Dockerfile

## Severity
**LOW** (score: 2.0/10)

An `update` run in its own Docker layer, separate from the install, is likely to be cached and skipped on rebuilds, causing images to silently ship with stale, potentially vulnerable package versions.

## Summary
This check fails a Dockerfile if a package-manager "update" command (e.g. `apt-get update`, `yum update`) appears in a `RUN` instruction without a corresponding install/upgrade command in the same (or another) `RUN` layer, since an update-only layer can be cached separately from the install step and become stale.

## Applicability
Dockerfiles — specifically `RUN` instructions.

## Why it matters
Docker caches each `RUN` layer independently based on the exact instruction text. If `RUN apt-get update` is written as its own instruction, separate from the subsequent `RUN apt-get install ...`, Docker can reuse the cached "update" layer on a rebuild even though the upstream package index has moved on since that layer was cached — meaning the later `install` step resolves package versions against a stale, out-of-date index. This can silently pull in old, vulnerable package versions even though the Dockerfile "runs update," defeating the very purpose of the update and giving a false sense that the image has current patches. The standard mitigation (and Docker's own official guidance) is to chain `update && install` in a single `RUN` layer so cache invalidation of one forces re-execution of the other, guaranteeing they're always run together against the same fresh index.

## How Checkov evaluates this
The check (`UpdateNotAlone`) scans every `RUN` instruction's content. For lines containing the word `"update"`, it further tests a regex (`\s+(?:--)?update(?!\S)`) to confirm it's really an update-style flag/word (not just a substring elsewhere) and increments an `update_cnt` counter for each match, recording that instruction's index. Separately, for each `RUN` instruction whose content contains any of a fixed list of install-type keywords (`install`, `source-install`, `reinstall`, `groupinstall`, `localinstall`, `add`, `upgrade`), it decrements `update_cnt`. After scanning all `RUN` instructions in the file, if `update_cnt` is `<= 0` (meaning every detected "update" was matched/offset by a corresponding install-type keyword, whether in the same or a different `RUN` line), the check PASSES. If `update_cnt` remains positive (more "update" occurrences than offsetting install keywords found anywhere in the Dockerfile), it FAILS and reports the specific `RUN` instructions containing the unmatched `update`.

## Non-compliant example
```dockerfile
FROM ubuntu:22.04

RUN apt-get update

RUN pip install requests
```

## Remediated example
```dockerfile
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install requests
```

## Remediation steps
1. Find every `RUN` line that performs an `update` (e.g. `apt-get update`, `apk update`, `yum update`, `dnf update`) without an install/upgrade command in the same instruction.
2. Merge the update and the install/upgrade into a single `RUN` instruction using `&&`, so they always execute together and the install always resolves against a freshly updated package index: `RUN apt-get update && apt-get install -y <packages>`.
3. Clean up package manager caches in the same layer (`rm -rf /var/lib/apt/lists/*` for apt, `--no-cache` for apk) to keep image size down and avoid stale cached metadata lingering in the image.
4. Avoid `RUN apt-get upgrade`/`dist-upgrade` in Dockerfiles altogether where possible — prefer rebuilding from an updated base image tag, since blanket upgrades reduce build reproducibility.
5. Re-run the scan against `images/l4t/Dockerfile` to confirm it now passes.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/dockerfile/checks/UpdateNotAlone.py
- Docker best practices (RUN cache/update+install pattern): https://docs.docker.com/build/building/best-practices/#apt-get
