param([Parameter(Mandatory)][string]$Kubeconfig,
      [Parameter(Mandatory)][Guid]$FixtureOid,
      [Parameter(Mandatory)][Guid]$ExpectedCustomerId,
      [ValidatePattern('^[a-z0-9-]+$')][string]$RunSuffix='20261001-v1', [switch]$Execute)
$ErrorActionPreference='Stop'
if ($FixtureOid -eq [Guid]::Empty -or $ExpectedCustomerId -eq [Guid]::Empty) { throw 'Explicit authorized DEV fixture required.' }
$namespace='azzu-web-dev'
$prefix='azzu-mapping-probe-' + $RunSuffix
function Submit($manifest) {
    $json=$manifest | ConvertTo-Json -Depth 50
    $json | kubectl --kubeconfig $Kubeconfig create --dry-run=server -f -
    if ($LASTEXITCODE -ne 0) { throw 'Server validation failed; no create' }
    if ($Execute) {
        $json | kubectl --kubeconfig $Kubeconfig create -f -
        if ($LASTEXITCODE -ne 0) { throw 'Create failed; no overwrite or broadened permissions' }
    }
}
$existingSa=kubectl --kubeconfig $Kubeconfig get serviceaccount azzu-web-bff -n $namespace --ignore-not-found -o json
if ($LASTEXITCODE -ne 0) { throw 'ServiceAccount check failed' }
if ($existingSa) {
    if (($existingSa | ConvertFrom-Json).metadata.annotations.'azure.workload.identity/client-id' -ne '6cdef73b-41a2-4aa5-b294-db6225286aed') {
        throw 'Unexpected BFF ServiceAccount identity'
    }
} else {
    Submit @{apiVersion='v1';kind='ServiceAccount';metadata=@{name='azzu-web-bff';namespace=$namespace;
        annotations=@{'azure.workload.identity/client-id'='6cdef73b-41a2-4aa5-b294-db6225286aed'}};automountServiceAccountToken=$false}
}
$proxyJson=kubectl --kubeconfig $Kubeconfig get service ts-identity-mapping-onprem-hhp9t -n tailscale -o json
if ($LASTEXITCODE -ne 0) { throw 'Mapping private proxy not found' }
$proxy=($proxyJson | ConvertFrom-Json).spec.selector.app
if ($proxy -ne '6c444037-099b-4add-863d-1e703d4b2da8') { throw 'Proxy selector changed; re-audit needed' }
$existingPolicy=kubectl --kubeconfig $Kubeconfig get networkpolicy csr-job-egress-allowlist -n $namespace -o json
if ($LASTEXITCODE -ne 0) { throw 'Existing Entra/vault allowlist unavailable' }
$egress=@(($existingPolicy | ConvertFrom-Json).spec.egress)
$egress+=@{to=@(@{namespaceSelector=@{matchLabels=@{'kubernetes.io/metadata.name'='tailscale'}};
    podSelector=@{matchLabels=@{app=$proxy}}});ports=@(@{protocol='TCP';port=7443})}
Submit @{apiVersion='networking.k8s.io/v1';kind='NetworkPolicy';metadata=@{name=$prefix+'-egress';namespace=$namespace};
    spec=@{podSelector=@{matchLabels=@{app='azzu-mapping-probe'}};policyTypes=@('Egress');egress=$egress}}

# Public precompiled diagnostic assemblies only. No certificates, source config or secrets in the bundle.
Add-Type -AssemblyName System.IO.Compression
$artifactPath=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\tools\Azzu.MappingProbe\bin\probe-artifact'))
$memory=[IO.MemoryStream]::new()
$archive=[IO.Compression.ZipArchive]::new($memory,[IO.Compression.ZipArchiveMode]::Create,$true)
try {
    $files=@(Get-ChildItem -LiteralPath $artifactPath -File)
    if ($files.Count -lt 1) { throw 'Build probe artifact first' }
    foreach ($file in $files) {
        if ($file.Extension -notin @('.dll','.json','.pdb')) { throw 'Unexpected diagnostic artifact type' }
        $entry=$archive.CreateEntry($file.Name,[IO.Compression.CompressionLevel]::Optimal)
        $source=[IO.File]::OpenRead($file.FullName); $destination=$entry.Open()
        try { $source.CopyTo($destination) } finally { $source.Dispose();$destination.Dispose() }
    }
} finally { $archive.Dispose() }
$bytes=$memory.ToArray();$memory.Dispose()
if ($bytes.Length -gt 16MB) { throw 'Diagnostic bundle unexpectedly large' }
$hash=[Security.Cryptography.SHA256]::Create()
$bundleHash=([BitConverter]::ToString($hash.ComputeHash($bytes))).Replace('-','').ToLowerInvariant();$hash.Dispose()
Write-Host "Diagnostic bundle bytes=$($bytes.Length), SHA256=$bundleHash"
$partVolumes=@();$partMounts=@();$partIndex=0
for ($offset=0;$offset -lt $bytes.Length;$offset+=512KB) {
    $length=[Math]::Min(512KB,$bytes.Length-$offset);$part=[byte[]]::new($length)
    [Array]::Copy($bytes,$offset,$part,0,$length)
    $partName=$prefix+'-part-'+$partIndex
    Submit @{apiVersion='v1';kind='ConfigMap';immutable=$true;metadata=@{name=$partName;namespace=$namespace};
        binaryData=@{part=[Convert]::ToBase64String($part)}}
    $partVolumes+=@{name='part-'+$partIndex;configMap=@{name=$partName}}
    $partMounts+=@{name='part-'+$partIndex;mountPath=('/parts/{0:d3}' -f $partIndex);readOnly=$true}
    $partIndex++
}
$assembler=@'
import hashlib, io, pathlib, zipfile
data=b''.join(p.read_bytes() for p in sorted(pathlib.Path('/parts').glob('*/part')))
import os
if hashlib.sha256(data).hexdigest()!=os.environ['BUNDLE_SHA256']: raise RuntimeError('artifact integrity failed')
with zipfile.ZipFile(io.BytesIO(data)) as archive:
    if sum(i.file_size for i in archive.infolist())>32*1024*1024: raise RuntimeError('artifact too large')
    for item in archive.infolist():
        if pathlib.PurePosixPath(item.filename).name!=item.filename: raise RuntimeError('unsafe artifact entry')
    archive.extractall('/app')
print('DIAGNOSTIC_ARTIFACT_INTEGRITY_PASS')
'@
Submit @{apiVersion='v1';kind='ConfigMap';immutable=$true;metadata=@{name=$prefix+'-public';namespace=$namespace};
    data=@{'assemble.py'=$assembler;'ca.crt'=(Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\..\docs\pki\ca.crt') -Raw)}}
$containerSecurity=@{runAsNonRoot=$true;allowPrivilegeEscalation=$false;readOnlyRootFilesystem=$true;capabilities=@{drop=@('ALL')}}
Submit @{apiVersion='batch/v1';kind='Job';metadata=@{name=$prefix;namespace=$namespace;labels=@{app='azzu-mapping-probe'}};
    spec=@{backoffLimit=0;activeDeadlineSeconds=240;template=@{
        metadata=@{labels=@{app='azzu-mapping-probe';'azure.workload.identity/use'='true'};
            annotations=@{'azure.workload.identity/skip-containers'='assemble'}}
        spec=@{serviceAccountName='azzu-web-bff';automountServiceAccountToken=$false;restartPolicy='Never';
            securityContext=@{runAsNonRoot=$true;runAsUser=10001;runAsGroup=10001;fsGroup=10001;seccompProfile=@{type='RuntimeDefault'}};
            initContainers=@(@{name='assemble';image='python@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e';
                command=@('python','-B','/public/assemble.py');securityContext=$containerSecurity;
                env=@(@{name='BUNDLE_SHA256';value=$bundleHash});
                resources=@{requests=@{cpu='50m';memory='64Mi'};limits=@{cpu='250m';memory='128Mi'}};
                volumeMounts=($partMounts+@(@{name='app';mountPath='/app'},@{name='public';mountPath='/public';readOnly=$true}))});
            containers=@(@{name='probe';image='mcr.microsoft.com/dotnet/runtime@sha256:37466ea190f696105c1c3ae67c15e32d4e199face9a0b2ad5b9a37c464db8f30';
                command=@('dotnet','/app/Azzu.MappingProbe.dll');securityContext=$containerSecurity;
                env=@(@{name='DOTNET_EnableDiagnostics';value='0'},@{name='DOTNET_ENVIRONMENT';value='Development'},
                    @{name='AZZU_PROBE_ENTRA_OID';value=$FixtureOid.ToString()},@{name='AZZU_PROBE_EXPECTED_CUSTOMER_ID';value=$ExpectedCustomerId.ToString()});
                resources=@{requests=@{cpu='100m';memory='128Mi'};limits=@{cpu='500m';memory='512Mi'}};
                volumeMounts=@(@{name='app';mountPath='/app';readOnly=$true},@{name='public';mountPath='/public';readOnly=$true},@{name='tmp';mountPath='/tmp'})});
            volumes=($partVolumes+@(@{name='app';emptyDir=@{medium='Memory';sizeLimit='64Mi'}},
                @{name='tmp';emptyDir=@{medium='Memory';sizeLimit='16Mi'}},@{name='public';configMap=@{name=$prefix+'-public'}}))
        }
    }}
}
