param([Parameter(Mandatory)][string]$Kubeconfig, [switch]$Execute)
$ErrorActionPreference='Stop'
$namespace='azzu-web-dev'
$prefix='azzu-server-csr-20261002-v1'
function Submit($manifest) {
    $json=$manifest | ConvertTo-Json -Depth 40
    $json | kubectl --kubeconfig $Kubeconfig create --dry-run=server -f -
    if ($LASTEXITCODE -ne 0) { throw 'Server validation failed; no write.' }
    if ($Execute) {
        $json | kubectl --kubeconfig $Kubeconfig create -f -
        if ($LASTEXITCODE -ne 0) { throw 'Create failed; no overwrite or permission changes.' }
    }
}
$sa=kubectl --kubeconfig $Kubeconfig get sa azzu-csr-generator -n $namespace -o json | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or $sa.metadata.annotations.'azure.workload.identity/client-id' -ne '02fc8537-31b3-41b5-a6a8-68f2ba4c0bb9') { throw 'Identity mismatch.' }
$template=kubectl --kubeconfig $Kubeconfig get job azzu-mapping-csr-20261001 -n $namespace -o json | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'Audited Job unavailable.' }
$pod=$template.spec.template.spec
if ($pod.serviceAccountName -ne 'azzu-csr-generator' -or $pod.containers.Count -ne 1 -or $pod.containers[0].image -ne 'python@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e' -or -not $pod.containers[0].securityContext.readOnlyRootFilesystem -or $pod.containers[0].securityContext.allowPrivilegeEscalation) { throw 'Security baseline mismatch.' }
$pod.containers[0].command=@('python','-B','/code/create-server-csr-job.py')
$pod.containers[0].env=@([pscustomobject]@{name='PYTHONUNBUFFERED';value='1'})
$pod.containers[0].volumeMounts=@($pod.containers[0].volumeMounts | Where-Object name -ne 'azure-identity-token')
$pod.volumes=@($pod.volumes | Where-Object name -ne 'azure-identity-token')
($pod.volumes | Where-Object name -eq 'code').configMap.name=$prefix+'-code'
($pod.volumes | Where-Object name -eq 'tmp').emptyDir=[pscustomobject]@{medium='Memory';sizeLimit='16Mi'}
Submit @{apiVersion='v1';kind='ConfigMap';immutable=$true;metadata=@{name=$prefix+'-code';namespace=$namespace};data=@{
    'create_csr_job.py'=(Get-Content (Join-Path $PSScriptRoot 'create-csr-job.py') -Raw)
    'create-server-csr-job.py'=(Get-Content (Join-Path $PSScriptRoot 'create-server-csr-job.py') -Raw)}}
Submit @{apiVersion='batch/v1';kind='Job';metadata=@{name=$prefix;namespace=$namespace;labels=@{app='azzu-csr-generator'}};spec=@{
    backoffLimit=0;activeDeadlineSeconds=240;template=@{metadata=@{labels=@{app='azzu-csr-generator';'azure.workload.identity/use'='true'}};spec=$pod}}}
