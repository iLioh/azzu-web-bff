param([Parameter(Mandatory)][string]$Kubeconfig,[switch]$Execute,
      [ValidatePattern('^[a-z0-9-]+$')][string]$RunSuffix='20261001', [switch]$InspectOnly)
$ErrorActionPreference='Stop'
$certDirectory=Join-Path $PSScriptRoot '..\..\docs\pki'
$openssl='C:\Program Files\Git\usr\bin\openssl.exe'
$leaf=Join-Path $certDirectory 'azzu-web-bff-dev-mapping-mtls.crt.pem'
$ca=Join-Path $certDirectory 'ca.crt'
$csr=Join-Path $certDirectory 'azzu-web-bff-dev-mapping-mtls.csr.pem'
& $openssl verify -purpose sslclient -CAfile $ca $leaf
if ($LASTEXITCODE -ne 0) { throw 'Certificate chain invalid' }
$certPublic=(& $openssl x509 -in $leaf -noout -pubkey) -join "`n"
$csrPublic=(& $openssl req -in $csr -noout -pubkey) -join "`n"
if ($certPublic -cne $csrPublic) { throw 'Certificate public key does not match CSR' }

function Submit-Manifest($manifest) {
    $json=$manifest | ConvertTo-Json -Depth 40
    $json | kubectl --kubeconfig $Kubeconfig create --dry-run=server -f -
    if ($LASTEXITCODE -ne 0) { throw 'Server validation failed' }
    if ($Execute) {
        $json | kubectl --kubeconfig $Kubeconfig create -f -
        if ($LASTEXITCODE -ne 0) { throw 'Create failed; no overwrite' }
    }
}
$config=@{
    apiVersion='v1';kind='ConfigMap';immutable=$true
    metadata=@{name=('azzu-csr-merge-code-' + $RunSuffix);namespace='azzu-web-dev'}
    data=@{
        'create-csr-job.py'=(Get-Content -LiteralPath (Join-Path $PSScriptRoot 'create-csr-job.py') -Raw)
        'merge-csr-job.py'=(Get-Content -LiteralPath (Join-Path $PSScriptRoot 'merge-csr-job.py') -Raw)
        'client.crt.pem'=(Get-Content -LiteralPath $leaf -Raw)
        'ca.crt'=(Get-Content -LiteralPath $ca -Raw)
    }
}
Submit-Manifest $config
# Reuse audited security settings and identity, not the completed Job itself.
$templateJson=kubectl --kubeconfig $Kubeconfig get job azzu-mapping-csr-20261001 -n azzu-web-dev -o json
if ($LASTEXITCODE -ne 0) { throw 'Original audited Job unavailable' }
$template=($templateJson | ConvertFrom-Json).spec.template
# Strip controller-generated labels, webhook token mount and injected env. The webhook
# regenerates them for this Job using the same dedicated ServiceAccount.
$podSpec=$template.spec
$container=$podSpec.containers[0]
$container.command=@('python','-B','/code/merge-csr-job.py')
$container.env=@([pscustomobject]@{name='PYTHONUNBUFFERED';value='1'})
if ($InspectOnly) { $container.env+= [pscustomobject]@{name='MERGE_INSPECT_ONLY';value='true'} }
$container.volumeMounts=@($container.volumeMounts | Where-Object { $_.name -ne 'azure-identity-token' })
$podSpec.volumes=@($podSpec.volumes | Where-Object { $_.name -ne 'azure-identity-token' })
($podSpec.volumes | Where-Object name -eq 'code').configMap.name='azzu-csr-merge-code-' + $RunSuffix
Submit-Manifest @{
    apiVersion='batch/v1';kind='Job'
    metadata=@{name=('azzu-mapping-cert-merge-' + $RunSuffix);namespace='azzu-web-dev';labels=@{app='azzu-csr-generator'}}
    spec=@{backoffLimit=0;activeDeadlineSeconds=300;template=@{
        metadata=@{labels=@{app='azzu-csr-generator';'azure.workload.identity/use'='true'}}
        spec=$podSpec
    }}
}
