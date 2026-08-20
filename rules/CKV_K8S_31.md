# CKV_K8S_31: Ensure that the seccomp profile is set to docker/default or runtime/default

## Severity
**LOW** (score: 2.0/10)

Running without a restrictive seccomp profile leaves the full host syscall surface available to a container process, meaningfully easing kernel-level exploitation or container-escape attempts after an initial compromise.

## Summary
This check ensures pods/containers use a restrictive seccomp profile (`RuntimeDefault`, or the legacy `docker/default`/`runtime/default` annotation values) rather than running with the unconfined default.

## Applicability
**Checkov framework(s):** `kubernetes`

Kubernetes manifests only, kinds: `Pod`, `Deployment`, `DaemonSet`, `StatefulSet`, `ReplicaSet`, `ReplicationController`, `Job`, `CronJob`. Inspected at both pod (`spec.securityContext.seccompProfile.type`) and container (`containers[].securityContext.seccompProfile.type`) level, plus the legacy annotation `seccomp.security.alpha.kubernetes.io/pod`.

## Why it matters
Seccomp (secure computing mode) restricts which Linux syscalls a container's process can invoke. Without a seccomp profile, a container runs "unconfined," meaning a process compromised via a code-execution vulnerability (or a malicious image) has access to the full syscall surface of the kernel, including many rarely-used and higher-risk syscalls (e.g. `ptrace`, `mount`, various namespace/kernel-module syscalls) that container escapes and kernel-exploit chains frequently rely on. The `RuntimeDefault` profile (or `docker/default`) blocks a curated list of dangerous syscalls not needed by ordinary application containers, meaningfully shrinking the kernel attack surface available to an attacker who gains code execution inside the container — this is one of the most impactful, close-to-free hardening controls available and is part of both the CIS Kubernetes Benchmark and the Pod Security Standards `restricted` profile.

## How Checkov evaluates this
The check walks the resource's spec structure by kind (`Pod` directly; `Deployment`/`StatefulSet`/`DaemonSet`/`Job`/`ReplicaSet` via `spec.template.spec`; `CronJob` via `spec.jobTemplate.spec.template.spec`):
1. First checks `securityContext.seccompProfile.type` at the pod level; if set, PASS only when the value is exactly `RuntimeDefault` (anything else, e.g. `Unconfined` or `Localhost`, FAILS).
2. If not set at pod level, checks each container's `securityContext.seccompProfile.type` — all containers must be `RuntimeDefault` to PASS; any container with a different explicit value FAILS immediately.
3. If neither modern field is set, falls back to the legacy alpha annotation `seccomp.security.alpha.kubernetes.io/pod` on metadata (or nested metadata for CronJob), and PASSES if its value contains `docker/default` or `runtime/default`.
4. If none of the above are found, the check FAILS (no profile configured at all = unconfined, which is not allowed).

## Non-compliant example
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  replicas: 1
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
        - name: app
          image: myrepo/web:1.4.0
```

## Remediated example
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  replicas: 1
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      securityContext:
        seccompProfile:
          type: RuntimeDefault   # added
      containers:
        - name: app
          image: myrepo/web:1.4.0
```

## Remediation steps
1. Add `spec.template.spec.securityContext.seccompProfile.type: RuntimeDefault` (pod-level) — this applies to all containers unless overridden.
2. Alternatively set it per-container under each container's `securityContext.seccompProfile.type`.
3. If any container has a genuine need for a custom or unconfined profile, use `Localhost` with a specific named profile file rather than `Unconfined`, and document the exception.
4. For clusters still on older Kubernetes (< 1.19) without the stable `seccompProfile` field, use the legacy annotation `seccomp.security.alpha.kubernetes.io/pod: "runtime/default"`.
5. Apply this fix to the base manifests behind the `observability`, `dash`, and `argo` kustomizations flagged in this repo, then re-scan.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/Seccomp.py)
- [Kubernetes docs: Restrict a Container's Syscalls with seccomp](https://kubernetes.io/docs/tutorials/security/seccomp/)
