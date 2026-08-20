# CKV_K8S_37: Minimize the admission of containers with capabilities assigned (container securityContext)

## Severity
**LOW** (score: 2.0/10)

Failing to explicitly drop ALL Linux capabilities leaves a container with the runtime's default capability set, which can be leveraged for privilege escalation or container-escape techniques if the container is compromised.

## Summary
This check ensures each container's `securityContext.capabilities.drop` explicitly includes `ALL`, so the container starts with no Linux capabilities rather than the runtime default set.

## Applicability
- **Kubernetes manifests**: container-level check across kinds `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`.
- **Terraform**: resource types `kubernetes_pod`, `kubernetes_pod_v1`, `kubernetes_deployment`, `kubernetes_deployment_v1`, at `spec.container[].security_context.capabilities.drop`.

## Why it matters
Container runtimes grant a non-trivial default Linux capability set even to non-root containers (e.g. `CHOWN`, `NET_RAW`, `SETUID`, `SETGID`, `FOWNER`, `DAC_OVERRIDE`), several of which provide real post-compromise value to an attacker: `NET_RAW` allows crafting raw packets (useful for spoofing/sniffing on the pod network), `SETUID`/`SETGID` can assist privilege manipulation, and `DAC_OVERRIDE` bypasses file permission checks entirely. This is the workload-level counterpart to CKV_K8S_36 (which enforces the same idea at the PodSecurityPolicy layer): rather than relying on a cluster-wide policy, each container should explicitly drop every capability it doesn't need (`drop: ["ALL"]`) and, only if truly required, re-add the minimal specific capability via `add`. Following CIS Benchmark 5.2.9, this is one of the highest-value, lowest-friction hardening steps because most application containers need zero elevated capabilities to function.

## How Checkov evaluates this
For each container, the check inspects `securityContext.capabilities.drop`: if the list exists and contains the string `ALL` or `all` (case handled via substring match against each entry), the check PASSES. If `securityContext`, `capabilities`, or `drop` is missing, or `drop` doesn't include `ALL`/`all`, the check FAILS. (In the Terraform version, if `capabilities` is present but has no `drop` list at all, it also FAILS.)

## Non-compliant example
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      containers:
        - name: app
          image: myrepo/web:1.4.0
          securityContext:
            runAsNonRoot: true
            # no capabilities.drop specified — retains default capability set
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
      containers:
        - name: app
          image: myrepo/web:1.4.0
          securityContext:
            runAsNonRoot: true
            capabilities:
              drop:
                - ALL   # drop all default Linux capabilities
```

## Remediation steps
1. Add `securityContext.capabilities.drop: ["ALL"]` to every container in the manifest.
2. If a container genuinely needs a specific capability (e.g. `NET_BIND_SERVICE` to bind a privileged port), add it back explicitly via `securityContext.capabilities.add`, keeping `drop: ["ALL"]` as the baseline.
3. For the affected `observability`, `dash`, and `argo` kustomization bases in this repo, add the `capabilities.drop: ["ALL"]` block to each container's `securityContext` and re-scan.
4. Test workloads after this change — some legacy images assume default capabilities (e.g. binding to port 80/443 as root) and may need code changes (run as non-privileged port, or add back `NET_BIND_SERVICE`) to keep working.

## References
- [Checkov check source (Kubernetes)](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/MinimizeCapabilities.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/kubernetes/MinimiseCapabilities.py)
- [Kubernetes docs: Configure a Security Context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
