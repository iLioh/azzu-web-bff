param([Parameter(Mandatory)][string]$Kubeconfig, [switch]$Execute)
$ErrorActionPreference='Stop'
$namespace='azzu-web-dev'
$prefix='azzu-oidc-cert-20261001-v1'
function Submit($manifest) {
    $json=$manifest | ConvertTo-Json -Depth 40
    $json | kubectl --kubeconfig $Kubeconfig create --dry-run=server -f -
    if ($LASTEXITCODE -ne 0) { throw 'Server validation failed; no write.' }
    if ($Execute) {
        $json | kubectl --kubeconfig $Kubeconfig create -f -
        if ($LASTEXITCODE -ne 0) { throw 'Create failed; no overwrite or privilege expansion.' }
    }
}
$sa = (kubectl --kubeconfig $Kubeconfig get sa azzu-csr-generator -n $namespace -o json | ConvertFrom-Json)
if ($LASTEXITCODE -ne 0 -or $sa.metadata.annotations.'azure.workload.identity/client-id' -ne '02fc8537-31b3-41b5-a6a8-68f2ba4c0bb9') { throw 'Provisioning identity mismatch.' }
$job = (kubectl --kubeconfig $Kubeconfig get job azzu-mapping-csr-20261001 -n $namespace -o json | ConvertFrom-Json)
if ($LASTEXITCODE -ne 0) { throw 'Audited security template unavailable.' }
$pod=$job.spec.template.spec
$container=$pod.containers[0]
$container.command=@('python','-B','/code/create-oidc-certificate-job.py')
$container.env=@([pscustomobject]@{name='PYTHONUNBUFFERED';value='1'})
$container.volumeMounts=@($container.volumeMounts | Where-Object name -ne 'azure-identity-token')
$pod.volumes=@($pod.volumes | Where-Object name -ne 'azure-identity-token')
($pod.volumes | Where-Object name -eq 'code').configMap.name=$prefix+'-code'
($pod.volumes | Where-Object name -eq 'tmp').emptyDir=[pscustomobject]@{medium='Memory';sizeLimit='16Mi'}
Submit @{apiVersion='v1';kind='ConfigMap';immutable=$true;metadata=@{name=$prefix+'-code';namespace=$namespace};
    data=@{'create_csr_job.py'=(Get-Content (Join-Path $PSScriptRoot 'create-csr-job.py') -Raw);
           'create-oidc-certificate-job.py'=(Get-Content (Join-Path $PSScriptRoot 'create-oidc-certificate-job.py') -Raw)}}
Submit @{apiVersion='batch/v1';kind='Job';metadata=@{name=$prefix;namespace=$namespace;labels=@{app='azzu-csr-generator'}};
    spec=@{backoffLimit=0;activeDeadlineSeconds=180;template=@{
        metadata=@{labels=@{app='azzu-csr-generator';'azure.workload.identity/use'='true'}};spec=$pod}}}
