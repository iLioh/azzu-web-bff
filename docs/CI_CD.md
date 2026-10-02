# Web BFF CI/CD

## Current versus prepared

CI runs on pull requests and `main`: Release build/tests, NuGet audit,
Linux read-only container smoke, Trivy HIGH/CRITICAL vulnerabilities and secrets,
CycloneDX SBOM and short-lived artifacts. Actions are pinned by commit.

Publication to DEV ACR uses GitHub environment `dev`, reviewer approval and Azure
OIDC federation. No permanent Azure credentials or kubeconfig are stored in GitHub.
The image is tagged with the commit SHA; existing tags cannot be overwritten.
Deployment consumes the resulting immutable `repository@sha256:digest`.

After explicit approval, the Azure federation subject was corrected to GitHub's
immutable repository/environment identity. Issuer, audience and roles were left
unchanged. Publication can now be enabled (`AZZU_BFF_PUBLISH_ENABLED=true`) but still
requires a DEV reviewer approval and successful build/scan.

**CD is prepared but disabled** (`AZZU_BFF_CD_ENABLED=false`). This is not a deployed
server or a working banking login. The current shared AKS has `aadProfile=null`;
the CI identity does not have namespace-scoped AKS authorization. AcrPush alone is
not Kubernetes deployment permission. No cluster authentication was changed.

## Activation gates requiring separate approval

1. Platform approves the shared cluster's managed Entra/Azure RBAC model and the
   connectivity of the release runner. Do not silently change authentication or
   use admin credentials. A private API server needs a runner with private access.
2. Give the release identity Cluster User access on the exact AKS resource and a
   custom Kubernetes release role at `azzu-web-dev` scope: read Deployments,
   ReplicaSets, Pods, Services and HPAs; update Deployments only as required.
   No Secrets, exec, RBAC management, namespace creation or other namespaces.
   The built-in RBAC Writer is not a substitute: it includes secret access.
   Review the custom role's actual Azure data actions before assigning it.
3. Bootstrap the approved namespace/workload privately in a separate reviewed
   deployment: Workload Identity, private TLS, DNS, dependencies, Cilium policies,
   default-deny, explicit Mapping/API allowlist, no direct PostgreSQL/Core access.
   Release jobs never bootstrap or change these resources.
4. Initial Service must be internal, IP `10.20.0.7`, 443 -> 8443. TLS must validate
   `web-bff.internal.azzu.tech` and its chain; no public A record for this host.
5. While token/session store is process-local: one replica, no HPA, `Recreate`.
   Releases interrupt existing sessions; DEV users must sign in again. Multi-replica
   rollout/HPA needs shared Data Protection keys AND a distributed session/token
   store with concurrency-safe refresh/revocation. Neither is claimed implemented.
6. Set exact compatible `AZZU_KUBECTL_VERSION` and `AZZU_KUBELOGIN_VERSION`, validate
   real RBAC, TLS and server-side preview, then explicitly enable CD.

## Release workflow

`main -> build/test/scan -> DEV approval -> ACR -> CD gate -> DEV approval ->
server dry-run image patch -> image-only patch -> rollout health`.

Manual dispatch can request publication or an approved DEV release. The CD job
fails closed if auth, permissions, existing deployment or private Service differs
from the baseline. Its optimistic resourceVersion test rejects concurrent changes.
It never applies Mobile manifests or requests Cluster Admin.

Two approvals are intentional: publishing an image does not approve AKS changes.
On rollback, review the recorded previous digest and approve an image-only update;
there is no automatic rollback that might restore an insecure/expired version.

## Variables (not secrets)

- `AZURE_BFF_CICD_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`.
- `AZZU_BFF_CD_ENABLED`: `false`; `AZZU_BFF_PUBLISH_ENABLED`: `true` after federation verification.
- Exact `AZZU_KUBECTL_VERSION` / `AZZU_KUBELOGIN_VERSION`: supplied at activation.

The former federation was `repo:iLioh/azzu-web-bff:environment:dev`. The verified,
approved subject is now `repo:iLioh@108911528/azzu-web-bff@1397241893:environment:dev`.
Do not weaken GitHub's immutable repository identity to hide this mismatch.
PRs cannot publish or deploy. GitHub approvals do not replace initial Azure change
approval. Protect `main` and workflow changes with repository review rules.

## Validation

`scripts/Test-BffRelease.ps1` mocks every kubectl call and tests preview plus nine
rejection scenarios without a cluster. Real cluster dry-run and login end-to-end
remain activation prerequisites, not results of those mocked checks.
