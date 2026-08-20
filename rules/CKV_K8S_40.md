# CKV_K8S_40: Containers should run as a high UID to avoid host conflict

## Severity
**LOW** (score: 2.0/10)

Running with a low UID mainly risks accidental collision with a real host user account rather than granting a meaningful attack path by itself, making this primarily a defense-in-depth hygiene control.

## Summary
This check ensures containers run with a UID of 10000 or higher (via `runAsUser` at pod or container level), rather than a low UID that might collide with a real user account on the host.

## Applicability
**Checkov framework(s):** `kubernetes`

Kubernetes manifests only, kinds: `Pod`, `Deployment`, `DaemonSet`, `StatefulSet`, `ReplicaSet`, `ReplicationController`, `Job`, `CronJob`. Inspected at `securityContext.runAsUser` at both pod and container scope.

## Why it matters
Containers share the host kernel's UID namespace with the node in the common (non-remapped) case: a container process with UID 1000, for example, is UID 1000 on the host too. If that UID happens to coincide with a real user account on the node (e.g. a service account used by node-level tooling, or another tenant's low-numbered UID in a shared/multi-tenant environment), a container escape or a shared-volume/hostPath mount could let the container read/write files owned by that host user, or a host process could be tricked into treating container-written files as belonging to a trusted UID. Using a high UID (≥ 10000), well outside the range typically assigned to real system or human accounts, sharply reduces the chance of an accidental privilege collision between container processes and host-level accounts. Note the check explicitly PASSES when `hostUsers: false` is set (Linux user-namespace pod isolation, available on newer Kubernetes), since that feature remaps container UIDs to unprivileged, non-colliding host UIDs, making the high-UID convention unnecessary.

## How Checkov evaluates this
The check extracts the pod spec (directly for `Pod`; via `spec.template.spec` or the CronJob nested path for other kinds). If `spec.hostUsers` is `false`, it PASSES immediately (user namespace isolation makes the concern moot). Otherwise it evaluates `runAsUser` at both pod level and each container level against the threshold 10000, with container values overriding the pod value:
- Pod `runAsUser` ≥ 10000, no container override below it → PASS.
- Pod `runAsUser` ≥ 10000, but any container overrides with < 10000 → FAIL.
- Pod `runAsUser` < 10000 (or absent) and no container overrides it to ≥ 10000 → FAIL.
- Pod `runAsUser` absent/< 10000, but every container explicitly sets `runAsUser` ≥ 10000 → PASS.
- Any container with `runAsUser` unset while the pod value is failing/absent → FAIL.

## Non-compliant example
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      securityContext:
        runAsUser: 1000    # low UID, risk of host collision
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
  template:
    spec:
      securityContext:
        runAsUser: 10001   # high UID, avoids host collision
      containers:
        - name: app
          image: myrepo/web:1.4.0
```

## Remediation steps
1. Set `securityContext.runAsUser` to a value of 10000 or higher at the pod level (applies to all containers unless overridden).
2. If a specific container's image hard-codes a lower UID for its own process ownership, override `runAsUser` at the container level with a value ≥ 10000, and ensure the image's file ownership/permissions are compatible (may require `fsGroup` or an init step to `chown` mounted volumes).
3. Alternatively, on Kubernetes versions/runtimes that support it, set `spec.hostUsers: false` to enable Linux user-namespace isolation, which remaps container UIDs so this concern no longer applies.
4. Apply the fix to the flagged `observability`, `dash`, and `cert-manager` bases in this repo; verify each container image can actually run as the chosen non-default UID (some images assume UID 0 or a specific low UID baked into `Dockerfile USER`).

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/RootContainersHighUID.py)
- [Kubernetes docs: Configure a Security Context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
