# CKV_DOCKER_11: Ensure From Alias are unique for multistage builds.

## Severity
**LOW** (score: 2.0/10)

Duplicate multistage build aliases are a correctness/maintainability defect (a later stage can unintentionally shadow an earlier one) rather than a direct security exposure.

## Summary
This check fails a Dockerfile using multistage builds if two or more `FROM ... AS <alias>` stages reuse the same alias name.

## Applicability
Dockerfiles — specifically `FROM` instructions that include an `AS <alias>` clause, used in multistage builds.

## Why it matters
In a multistage Dockerfile, later stages and `COPY --from=<alias>` instructions reference an earlier stage by its alias. If two stages share the same alias, any reference to that alias becomes ambiguous — Docker resolves it based on build-stage ordering rules, which means `COPY --from=<alias>` could silently pull files from a *different* stage than the author intended (typically the last stage sharing that name, depending on Docker's/BuildKit's resolution behavior). This can lead to build artifacts, binaries, or configuration files being copied from the wrong build stage into the final image without any error — e.g., accidentally including debug tooling, build-time secrets/credentials that were only supposed to exist in an intermediate stage, or an older/different version of an artifact than the one just built. Because there's no build failure, this class of bug can go unnoticed until it manifests as a functional or security problem in the shipped image.

## How Checkov evaluates this
The check (`AliasIsUnique`) scans every `FROM` instruction's value string. For any `FROM` value containing `" as "` (case handling depends on how the Dockerfile parser normalizes it), it extracts the alias as the last whitespace-separated token of that value and appends it to a list. After processing all `FROM` instructions, it compares the length of that alias list to the length of the deduplicated `set()` of aliases. If they're equal (no duplicates), the check PASSES. If the set is smaller than the list (i.e., at least one alias was reused), the check FAILS, reporting the first `FROM` instruction in the file as the failing entity.

## Non-compliant example
```dockerfile
FROM golang:1.22 AS build
WORKDIR /src
COPY . .
RUN go build -o /out/app .

FROM alpine:3.19 AS build
RUN apk add --no-cache ca-certificates

FROM alpine:3.19
COPY --from=build /out/app /usr/local/bin/app
CMD ["/usr/local/bin/app"]
```

## Remediated example
```dockerfile
FROM golang:1.22 AS build
WORKDIR /src
COPY . .
RUN go build -o /out/app .

FROM alpine:3.19 AS certs
RUN apk add --no-cache ca-certificates

FROM alpine:3.19
COPY --from=build /out/app /usr/local/bin/app
COPY --from=certs /etc/ssl/certs /etc/ssl/certs
CMD ["/usr/local/bin/app"]
```

## Remediation steps
1. Give every `FROM ... AS <alias>` stage in the Dockerfile a distinct, descriptive alias (e.g. `build`, `certs`, `test`, `runtime`) instead of reusing the same name.
2. Double-check every `COPY --from=<alias>` (and any multistage `FROM <alias>` reuse) still points at the intended stage after renaming.
3. If the Dockerfile was produced by templating/generation, ensure the template assigns a unique alias per generated stage rather than a static one.
4. Re-run the scan to confirm the check now passes, and rebuild the image to verify the copied artifacts are still the ones expected.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/dockerfile/checks/AliasIsUnique.py
- Docker multistage builds reference: https://docs.docker.com/build/building/multi-stage/
