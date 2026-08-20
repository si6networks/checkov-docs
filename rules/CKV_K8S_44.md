# CKV_K8S_44: Ensure that the Tiller Service (Helm v2) is deleted

## Severity
**LOW** (score: 2.0/10)

A Service that exposes the highly privileged, unauthenticated-by-default Tiller gRPC endpoint extends that cluster-admin-equivalent access to anything on the network that can reach the Service, turning a dangerous component into a remotely reachable one.

## Summary
This check flags Kubernetes `Service` resources that expose the Tiller (Helm v2) component, identified by name, labels, or selector.

## Applicability
- **Kubernetes manifests**: resource kind `Service`.
- **Terraform**: resource types `kubernetes_service`, `kubernetes_service_v1`.

## Why it matters
Tiller exposed a gRPC API inside the cluster network with no authentication of its own, relying entirely on network-level access control — meaning any pod or process that could reach the Tiller `Service`'s ClusterIP could issue install/upgrade/delete commands for Helm releases cluster-wide, typically with the broad (often `cluster-admin`) privileges Tiller itself ran with. A `Service` object routing traffic to Tiller is therefore not just an unused legacy component but an active, reachable attack surface: removing the `Deployment`/`Pod` running Tiller (CKV_K8S_34) without also removing the `Service` that fronts it can leave a stale but still-functional network path, or signal that Tiller is still deployed somewhere in the cluster. This check specifically targets the `Service` object as an independent signal, since Services are sometimes retained even after workloads are decommissioned.

## How Checkov evaluates this
The Kubernetes check inspects the `Service`'s `metadata.name` (FAIL if it contains `tiller`, case-insensitive), `metadata.labels` (FAIL if any label value contains `tiller`, case-insensitive), and `spec.selector` (FAIL if any selector value contains `tiller`, case-insensitive). If none of these match, and none of the fields needed to make a determination exist, the result is `UNKNOWN`. The Terraform check applies similar logic (name/label checks against `app == "helm"` or `name == "tiller"`, plus selector-value substring `tiller`) and returns PASS if a selector exists but doesn't match, `UNKNOWN` if there's no spec/selector to evaluate at all.

## Non-compliant example
```yaml
apiVersion: v1
kind: Service
metadata:
  name: tiller-deploy
  namespace: kube-system
  labels:
    app: helm
    name: tiller
spec:
  ports:
    - name: tiller
      port: 44134
      targetPort: tiller
  selector:
    app: helm
    name: tiller
```

## Remediated example
```yaml
# Delete the Tiller Service entirely — Helm v2/Tiller should not be running
# anywhere in the cluster. Migrate to Helm v3 (client-side only, no server
# component or Service required).
```

## Remediation steps
1. Delete the Tiller `Service` object (`kubectl delete svc tiller-deploy -n kube-system`) along with the corresponding Tiller `Deployment` (see CKV_K8S_34).
2. Remove any Terraform/IaC definitions that provision `kubernetes_service`/`kubernetes_service_v1` for Tiller.
3. Confirm no remaining CI/CD tooling or scripts reference the Tiller gRPC endpoint (`tiller-deploy.kube-system.svc:44134`) before removal.
4. Complete migration to Helm v3, verifying via `helm-2to3` that any release state has been converted before decommissioning the last Tiller components.
5. Audit RBAC bound to the Tiller ServiceAccount and revoke it once Tiller is fully removed.

## References
- [Checkov check source (Kubernetes)](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/TillerService.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/kubernetes/TillerService.py)
- [Helm docs: Migrate from Helm v2 to v3](https://helm.sh/docs/topics/v2_v3_migration/)
