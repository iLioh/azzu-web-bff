param([Parameter(Mandatory)][string]$Kubeconfig, [switch]$Execute)
$ErrorActionPreference='Stop'
$namespace='azzu-web-dev'
$prefix='azzu-server-merge-20261002-v1'
$publicDir=Join-Path $PSScriptRoot '../../.azure/pki/acme-issued-public-production'
$verification=Get-Content (Join-Path $publicDir 'public-verification.json') -Raw | ConvertFrom-Json
$chain=Get-Content (Join-Path $publicDir 'server-chain.pem') -Raw
if ($verification.certificateName -ne 'azzu-web-bff-dev-server-tls' -or $verification.hostname -ne 'web-bff.internal.azzu.tech' -or -not $verification.systemTrustVerified -or $verification.certificateSha256 -ne '5611F420661D5CC6CC545E9FDEB6BF8A4AEC6B6A7BCF8BA6EBD6234191FCC6A3' -or $chain -match 'PRIVATE KEY') { throw 'Reviewed public certificate gate failed.' }
& 'C:/Program Files/Git/usr/bin/openssl.exe' verify -purpose sslserver -verify_hostname web-bff.internal.azzu.tech -CAfile 'C:/Program Files/Git/usr/ssl/certs/ca-bundle.crt' -untrusted (Join-Path $publicDir 'server-intermediates.pem') (Join-Path $publicDir 'server-leaf.pem')
if ($LASTEXITCODE -ne 0) { throw 'Server chain/hostname gate failed.' }
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
$pod.containers[0].command=@('python','-B','/code/merge-server-csr-job.py')
$pod.containers[0].env=@([pscustomobject]@{name='PYTHONUNBUFFERED';value='1'})
$pod.containers[0].volumeMounts=@($pod.containers[0].volumeMounts | Where-Object name -ne 'azure-identity-token')
$pod.volumes=@($pod.volumes | Where-Object name -ne 'azure-identity-token')
($pod.volumes | Where-Object name -eq 'code').configMap.name=$prefix+'-code'
($pod.volumes | Where-Object name -eq 'tmp').emptyDir=[pscustomobject]@{medium='Memory';sizeLimit='16Mi'}
Submit @{apiVersion='v1';kind='ConfigMap';immutable=$true;metadata=@{name=$prefix+'-code';namespace=$namespace};data=@{
    'create_csr_job.py'=(Get-Content (Join-Path $PSScriptRoot 'create-csr-job.py') -Raw)
    'merge-server-csr-job.py'=(Get-Content (Join-Path $PSScriptRoot 'merge-server-csr-job.py') -Raw)
    'server-chain.pem'=$chain
    'server-verification.json'=(Get-Content (Join-Path $publicDir 'public-verification.json') -Raw)}}
Submit @{apiVersion='batch/v1';kind='Job';metadata=@{name=$prefix;namespace=$namespace;labels=@{app='azzu-csr-generator'}};spec=@{
    backoffLimit=0;activeDeadlineSeconds=240;template=@{metadata=@{labels=@{app='azzu-csr-generator';'azure.workload.identity/use'='true'}};spec=$pod}}}
