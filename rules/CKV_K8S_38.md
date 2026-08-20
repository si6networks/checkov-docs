# CKV_K8S_38: Ensure that Service Account Tokens are only mounted where necessary

## Severity
**LOW** (score: 2.0/10)

Auto-mounting a service account token into a pod that has no need to call the Kubernetes API gives any process compromising that container a live credential it can use to query or act against the cluster API, an unnecessary lateral-movement foothold.

## Summary
This check ensures pods explicitly set `automountServiceAccountToken: false` unless the workload actually needs to call the Kubernetes API from inside the container.

## Applicability
Kubernetes manifests only, kinds: `Pod`, `Deployment`, `DaemonSet`, `StatefulSet`, `ReplicaSet`, `ReplicationController`, `Job`, `CronJob`. Inspected at `spec.automountServiceAccountToken` (or the equivalent nested path for CronJob/Deployment-style templates).

## Why it matters
By default, Kubernetes automatically mounts the pod's ServiceAccount token (a JWT usable to authenticate to the Kubernetes API) into every container at `/var/run/secrets/kubernetes.io/serviceaccount/token`, whether or not the application ever calls the API. If an attacker achieves remote code execution inside such a container (e.g. via a vulnerable dependency), that mounted token becomes a ready-made credential for pivoting into the Kubernetes API itself — its scope depends on whatever RBAC the ServiceAccount has, but even "no special permissions" service accounts can often still discover cluster metadata, other pods, or namespaces, aiding further attack. CIS Benchmark 5.1.6 recommends disabling automount by default and only enabling it on the specific pods (typically operators, controllers, or CI tooling) that genuinely need in-cluster API access, drastically reducing the number of containers holding a live Kubernetes credential.

## How Checkov evaluates this
The check locates the relevant pod spec by kind — directly for `Pod`, via `spec.jobTemplate.spec.template.spec` for `CronJob`, and via `spec.template.spec` for all other supported kinds — then checks `automountServiceAccountToken`. If that field is explicitly set to `False`, PASS. Otherwise (field absent, `true`, or any other value) it FAILS — note that an absent field still fails here even though the Kubernetes runtime default would mount the token, since the check requires explicit opt-out.

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
      # automountServiceAccountToken not set -> defaults to true, token mounted
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
      automountServiceAccountToken: false   # added
      containers:
        - name: app
          image: myrepo/web:1.4.0
```

## Remediation steps
1. Add `spec.template.spec.automountServiceAccountToken: false` to every workload that does not call the Kubernetes API from within the container.
2. For workloads that do need API access (e.g. controllers, operators, `kubectl`-based init jobs), leave it enabled but bind a dedicated, least-privilege ServiceAccount (not `default`) with only the RBAC verbs/resources actually required.
3. Apply this to the flagged `observability`, `dash`, and `cert-manager` kustomization bases in this repo — note `cert-manager`'s own controller components legitimately need API access, so audit each Deployment individually rather than disabling automount blanket-wide.
4. Verify after the change that no application unexpectedly relies on the mounted token (check logs for API authentication failures) before rolling out broadly.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/ServiceAccountTokens.py)
- [Kubernetes docs: Configure Service Accounts for Pods](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/)
