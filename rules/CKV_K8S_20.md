# CKV_K8S_20: Containers should not run with allowPrivilegeEscalation
## Severity
**MEDIUM** (score: 5.0/10)

Allowing privilege escalation lets a process gain more privileges than its parent (e.g. via setuid binaries), which is a common stepping stone from initial container compromise to root/host access.

## Summary
This check fails any container whose `securityContext.allowPrivilegeEscalation` is not explicitly set to `false`, since Kubernetes defaults this setting to allow privilege escalation (e.g. via setuid binaries) unless it is explicitly disabled.

## Applicability
**Checkov framework(s):** `kubernetes`, `terraform`

- **IaC framework:** Kubernetes manifests (YAML/JSON) and Terraform
- **Resource/entity types (Kubernetes):** `Pod`, `PodTemplate`, `Deployment`, `DeploymentConfig`, `ReplicaSet`, `ReplicationController`, `StatefulSet`, `DaemonSet`, `Job`, `CronJob`
- **Resource/entity types (Terraform):** `kubernetes_pod`, `kubernetes_pod_v1`, `kubernetes_deployment`, `kubernetes_deployment_v1`

## Why it matters
`allowPrivilegeEscalation` controls whether a process inside a container can gain more privileges than its parent process — most commonly via setuid/setgid binaries or file capabilities (e.g. `sudo`, `ping`, or a maliciously modified binary with the setuid bit set). Kubernetes defaults this to `true` (to avoid breaking legacy setuid-dependent binaries), meaning that unless a manifest explicitly opts out, any container can escalate privileges within its own namespace if an exploitable setuid binary exists in its image. This is especially dangerous combined with other misconfigurations: a container is *always* considered to allow privilege escalation if it runs `privileged: true` or holds the `CAP_SYS_ADMIN` capability, regardless of this field's value — but for the many containers that are not privileged, explicitly setting `allowPrivilegeEscalation: false` closes off a real local-escalation path that attackers use after gaining initial code execution in a container (e.g. via a vulnerable application dependency). This maps to CIS Kubernetes Benchmark 1.7.5 / 5.2.5 and is required by the Pod Security Standards "Restricted" profile.

## How Checkov evaluates this
- **Kubernetes-native (`AllowPrivilegeEscalation`):** for each container, checks whether `securityContext.allowPrivilegeEscalation` is explicitly `False`. If so, PASSED. In every other case — field absent, `true`, or `securityContext` missing entirely — the check returns FAILED (note this check has no implicit "pass on absence" default, unlike most other securityContext checks).
- **Terraform:** inspects `spec[0].container[*].security_context[0].allow_privilege_escalation` (following `template[0].spec[0]` for Deployments). Fails only if the value is explicitly `[True]`; otherwise passes (including when absent), which differs slightly from the Kubernetes-native implementation's stricter default-fail behavior.

## Non-compliant example
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
spec:
  template:
    spec:
      containers:
        - name: app
          image: myorg/web-app:1.0
          securityContext: {}   # allowPrivilegeEscalation not set -> defaults to true
```

## Remediated example
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
spec:
  template:
    spec:
      containers:
        - name: app
          image: myorg/web-app:1.0
          securityContext:
            allowPrivilegeEscalation: false
```

## Remediation steps
1. Add `securityContext.allowPrivilegeEscalation: false` explicitly to every container (and initContainer) in Pod templates — do not rely on the implicit default.
2. Since our `kustomization.yaml` overlays under `pmx/cloud/simulations/k8s-manifests/*` are triggering this, add a strategic-merge or JSON6902 patch in the relevant `base`/`overlays` directories that injects this field into every container's `securityContext`, or add it directly in the base Deployment/Pod manifests referenced by the kustomization.
3. Combine with `privileged: false` and dropping `CAP_SYS_ADMIN` — both bypass this setting entirely and must also be corrected (see CKV_K8S_16 and CKV_K8S_28) for the fix to be effective.
4. Enforce cluster-wide with Pod Security Admission `restricted` profile so future manifests missing this field are rejected at admission time.
5. Test after applying — if any legitimate binary relied on setuid escalation inside the container, you may need to redesign the image (e.g. drop the setuid bit, run as non-root with only required capabilities) rather than re-enabling escalation.

## References
- [Checkov check source (Kubernetes)](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/AllowPrivilegeEscalation.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/kubernetes/AllowPrivilegeEscalation.py)
- [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
