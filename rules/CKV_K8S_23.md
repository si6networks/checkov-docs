# CKV_K8S_23: Minimize the admission of root containers
## Severity
**MEDIUM** (score: 5.0/10)

Running containers as root increases the impact of any container-breakout vulnerability by handing an attacker root-equivalent capabilities inside (and potentially outside) the container immediately.

## Summary
This check fails Pods/workloads where neither the Pod's nor its containers' security context reliably ensures the container process runs as a non-root user (via `runAsNonRoot: true` or `runAsUser` set to a non-zero UID), since running as root inside a container significantly increases the impact of any container escape or kernel exploit.

## Applicability
- **IaC framework:** Kubernetes manifests (YAML/JSON) only (no Terraform implementation for this specific rule ID)
- **Resource/entity types:** `Pod`, `Deployment`, `DaemonSet`, `StatefulSet`, `ReplicaSet`, `ReplicationController`, `Job`, `CronJob`

## Why it matters
Container UID 0 ("root" inside the container) is not the same as host root, but it still carries meaningfully more risk than a non-root UID: many container-breakout techniques and kernel vulnerabilities specifically require or are far easier to exploit from a root-owned process (e.g. certain namespace/cgroup escapes, writable `/proc` entries, or Docker/`runc` CVEs that only matter if the calling process is UID 0). Root inside the container also typically means unrestricted write access to any file the image ships with, unrestricted access to any mounted volume regardless of file ownership/permissions, and the ability to bind low (<1024) network ports. Enforcing non-root execution (CIS Kubernetes Benchmark 1.7.6 / 5.2.6, and mandatory under the Pod Security Standards "Restricted" profile) is one of the most effective single mitigations against container-to-host escalation.

## How Checkov evaluates this
The check (`RootContainers`, subclass of `BaseK8sRootContainerCheck`) evaluates a matrix of Pod-level and container-level settings:
1. Extracts the effective `spec` (via `Pod.spec`, `CronJob.spec.jobTemplate.spec.template.spec`, or `*.spec.template.spec`).
2. Computes `runAsNonRoot` and `runAsUser > 0` (PASSED/FAILED/ABSENT) at the **Pod level** and independently for **each container**, since container-level `securityContext` overrides the Pod-level setting.
3. Evaluation logic (container settings override Pod settings):
   - If Pod-level `runAsNonRoot == PASSED`: overall PASSED unless some container explicitly sets `runAsNonRoot: false` **and** that container's `runAsUser` is also FAILED/ABSENT (i.e., a container opts back into running as root without a fixed non-root UID).
   - Else if Pod-level `runAsUser > 0` (PASSED): overall PASSED unless a container explicitly overrides with a failing `runAsUser` (e.g. UID 0).
   - Else (Pod-level provides no non-root guarantee): overall PASSED only if every container individually sets `runAsNonRoot: true`, or otherwise sets a passing `runAsUser > 0`. Any container lacking both is FAILED.

## Non-compliant example
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: metrics-exporter
spec:
  template:
    spec:
      containers:
        - name: exporter
          image: myorg/exporter:1.0
          # no securityContext at pod or container level -> defaults to running as image's default user (often root)
```

## Remediated example
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: metrics-exporter
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
      containers:
        - name: exporter
          image: myorg/exporter:1.0
```

## Remediation steps
1. Add `runAsNonRoot: true` and a fixed non-zero `runAsUser` at the Pod-level `securityContext` for the affected Deployments under `pmx/cloud/simulations/k8s-manifests/{observability,dash,sim}` (via Kustomize patches on their `kustomization.yaml` bases/overlays).
2. Ensure the container image actually supports running as that non-root UID (owns/can write required directories, doesn't require binding privileged ports, etc.) — many base images (e.g. `nginx`, `postgres`) need specific non-root variants or `USER` directives set in the Dockerfile.
3. Where individual containers must temporarily differ from the Pod default, set container-level `securityContext.runAsNonRoot`/`runAsUser` explicitly rather than leaving it unset, since unset container-level fields inherit the Pod's setting but explicit false without a valid `runAsUser` fails the check.
4. Enforce via Pod Security Admission (`restricted` profile requires `runAsNonRoot: true`) so future manifests are validated automatically.
5. For images you don't control that hardcode running as root, consider a wrapper Dockerfile with a `USER` directive, or file ownership adjustments (`chown`) at build time so a non-root runtime user has the access it needs.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/RootContainers.py)
- [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Kubernetes: Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
