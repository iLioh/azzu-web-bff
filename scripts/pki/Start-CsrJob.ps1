param(
    [Parameter(Mandatory)][string]$ClientId,
    [Parameter(Mandatory)][string]$Kubeconfig,
    [switch]$Execute
)
$ErrorActionPreference = 'Stop'
$subscription = '8466fec9-2d75-4f1b-9bd7-52ea3e024ab9'
$namespace = 'azzu-web-dev'
$jobName = 'azzu-mapping-csr-20261001'

function Invoke-Manifest($Manifest) {
    $serialized = $Manifest | ConvertTo-Json -Depth 40
    if ($Execute) {
        $serialized | kubectl --kubeconfig $Kubeconfig create --dry-run=server -f -
        if ($LASTEXITCODE -ne 0) { throw 'Server validation failed; resource not created.' }
        $serialized | kubectl --kubeconfig $Kubeconfig create -f -
    } else {
        $serialized | kubectl --kubeconfig $Kubeconfig create --dry-run=server -f -
    }
    if ($LASTEXITCODE -ne 0) { throw 'Manifest creation/validation failed; stop without overwriting resources.' }
}

# Snapshot authoritative Entra service-tag prefixes; no generic Internet HTTPS allow.
# FQDN policy is not used because the cluster L7 proxy is disabled (ACNS is not enabled).
$prefixJson = az network list-service-tags --subscription $subscription --location chilecentral --query "values[?name=='AzureActiveDirectory'].properties.addressPrefixes[]" -o json
if ($LASTEXITCODE -ne 0) { throw 'Cannot obtain Entra destination allowlist.' }
$prefixes = @($prefixJson | ConvertFrom-Json | Where-Object { $_ -notmatch ':' })
if ($prefixes.Count -lt 1) { throw 'Empty Entra allowlist.' }
$httpsDestinations = @(@{ipBlock=@{cidr='10.20.5.22/32'}}) + @($prefixes | ForEach-Object { @{ipBlock=@{cidr=$_}} })
Write-Host "Entra service-tag IPv4 prefixes: $($prefixes.Count). Private vault destination: 10.20.5.22/32."

Invoke-Manifest @{
    apiVersion='v1'; kind='ServiceAccount'
    metadata=@{name='azzu-csr-generator'; namespace=$namespace; annotations=@{'azure.workload.identity/client-id'=$ClientId}}
    automountServiceAccountToken=$false
}
Invoke-Manifest @{
    apiVersion='networking.k8s.io/v1'; kind='NetworkPolicy'
    metadata=@{name='csr-job-egress-allowlist';namespace=$namespace}
    spec=@{
        podSelector=@{matchLabels=@{app='azzu-csr-generator'}}
        policyTypes=@('Egress')
        egress=@(
            @{to=@(@{namespaceSelector=@{matchLabels=@{'kubernetes.io/metadata.name'='kube-system'}};podSelector=@{matchLabels=@{'k8s-app'='kube-dns'}}});ports=@(@{protocol='UDP';port=53},@{protocol='TCP';port=53})},
            @{to=$httpsDestinations;ports=@(@{protocol='TCP';port=443})}
        )
    }
}
Invoke-Manifest @{
    apiVersion='v1';kind='ConfigMap'
    metadata=@{name='azzu-csr-generator-code';namespace=$namespace}
    immutable=$true
    data=@{'create-csr-job.py'=(Get-Content -LiteralPath (Join-Path $PSScriptRoot 'create-csr-job.py') -Raw)}
}
Invoke-Manifest @{
    apiVersion='batch/v1';kind='Job'
    metadata=@{name=$jobName;namespace=$namespace;labels=@{app='azzu-csr-generator'}}
    spec=@{
        backoffLimit=0;activeDeadlineSeconds=600
        template=@{
            metadata=@{labels=@{app='azzu-csr-generator';'azure.workload.identity/use'='true'}}
            spec=@{
                serviceAccountName='azzu-csr-generator';automountServiceAccountToken=$false;restartPolicy='Never'
                securityContext=@{runAsNonRoot=$true;runAsUser=10001;runAsGroup=10001;fsGroup=10001;seccompProfile=@{type='RuntimeDefault'}}
                containers=@(@{
                    name='csr';image='python@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e';imagePullPolicy='IfNotPresent'
                    command=@('python','-B','/code/create-csr-job.py')
                    env=@(@{name='PYTHONUNBUFFERED';value='1'})
                    securityContext=@{runAsNonRoot=$true;allowPrivilegeEscalation=$false;readOnlyRootFilesystem=$true;capabilities=@{drop=@('ALL')}}
                    resources=@{requests=@{cpu='50m';memory='64Mi'};limits=@{cpu='250m';memory='128Mi'}}
                    volumeMounts=@(@{name='code';mountPath='/code';readOnly=$true},@{name='tmp';mountPath='/tmp'})
                })
                volumes=@(@{name='code';configMap=@{name='azzu-csr-generator-code'}},@{name='tmp';emptyDir=@{sizeLimit='16Mi'}})
            }
        }
    }
}
