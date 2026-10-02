$ErrorActionPreference = 'Stop'
$releaseScript = Join-Path $PSScriptRoot 'Update-BffRelease.ps1'
$global:azzuReleaseTestState = @{ scenario = 'valid'; patches = 0; rollouts = 0 }
function kubectl {
    $argv = @($args)
    $global:LASTEXITCODE = 0
    if ($argv[0] -eq 'patch') {
        $global:azzuReleaseTestState.patches++
        if ($argv -notcontains '--dry-run=server') { throw 'Test must never issue a live patch.' }
        $patchIndex = [Array]::IndexOf($argv, '--patch')
        $operations = @($argv[$patchIndex + 1] | ConvertFrom-Json)
        if ($operations.Count -ne 3 -or $operations[2].path -ne '/spec/template/spec/containers/0/image') { throw 'Patch is not image-only.' }
        return 'deployment.apps/azzu-web-bff (server dry run)'
    }
    if ($argv[0] -eq 'rollout') { $global:azzuReleaseTestState.rollouts++; throw 'No rollout is allowed during preview tests.' }
    if ($argv[0] -ne 'get' -or $argv -notcontains 'azzu-web-dev') { throw 'Unexpected Kubernetes operation.' }
    if ($global:azzuReleaseTestState.scenario -eq 'read-error') { $global:LASTEXITCODE = 1; return '' }
    switch ($argv[1]) {
        'deployment' {
            $item = @{
                metadata = @{ namespace = 'azzu-web-dev'; name = 'azzu-web-bff'; resourceVersion = '12' }
                spec = @{ replicas = 1; strategy = @{ type = 'Recreate' }; template = @{
                    metadata = @{ labels = @{ 'azure.workload.identity/use' = 'true' } }
                    spec = @{ serviceAccountName = 'azzu-web-bff'; automountServiceAccountToken = $false
                        securityContext = @{ runAsNonRoot = $true; seccompProfile = @{ type = 'RuntimeDefault' } }
                        containers = @(@{ name = 'web-bff'; image = 'previous@sha256:test'
                            securityContext = @{ readOnlyRootFilesystem = $true; allowPrivilegeEscalation = $false; capabilities = @{ drop = @('ALL') } }
                            readinessProbe = @{ httpGet = @{ scheme = 'HTTPS'; port = 8443; path = '/health/ready' } }
                            livenessProbe = @{ httpGet = @{ scheme = 'HTTPS'; port = 8443; path = '/health/live' } }
                        })
                    }
                } }
            }
            if ($global:azzuReleaseTestState.scenario -eq 'two-replicas') { $item.spec.replicas = 2 }
            if ($global:azzuReleaseTestState.scenario -eq 'rolling') { $item.spec.strategy.type = 'RollingUpdate' }
            if ($global:azzuReleaseTestState.scenario -eq 'wrong-sa') { $item.spec.template.spec.serviceAccountName = 'default' }
            if ($global:azzuReleaseTestState.scenario -eq 'writable') { $item.spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem = $false }
            if ($global:azzuReleaseTestState.scenario -eq 'http') { $item.spec.template.spec.containers[0].readinessProbe.httpGet.scheme = 'HTTP' }
            return ($item | ConvertTo-Json -Depth 20)
        }
        'service' {
            $item = @{ metadata = @{ annotations = @{ 'service.beta.kubernetes.io/azure-load-balancer-internal' = 'true' } }
                spec = @{ type = 'LoadBalancer'; ports = @(@{ port = 443; targetPort = 8443 }) }
                status = @{ loadBalancer = @{ ingress = @(@{ ip = '10.20.0.7' }) } } }
            if ($global:azzuReleaseTestState.scenario -eq 'public') { $item.metadata.annotations.'service.beta.kubernetes.io/azure-load-balancer-internal' = 'false' }
            return ($item | ConvertTo-Json -Depth 10)
        }
        'hpa' {
            $items = @()
            if ($global:azzuReleaseTestState.scenario -eq 'hpa') { $items = @(@{ spec = @{ scaleTargetRef = @{ name = 'azzu-web-bff' } } }) }
            return (@{ items = $items } | ConvertTo-Json -Depth 10)
        }
        default { throw 'Unexpected resource type.' }
    }
}
$digest = 'acrneobancoazzu8466fe.azurecr.io/azzu-web-bff@sha256:' + ('a' * 64)
& $releaseScript -ImageDigest $digest -Preview
if ($global:azzuReleaseTestState.patches -ne 1 -or $global:azzuReleaseTestState.rollouts -ne 0) { throw 'Preview did not behave as expected.' }
foreach ($case in @('two-replicas', 'rolling', 'wrong-sa', 'writable', 'http', 'public', 'hpa', 'read-error')) {
    $global:azzuReleaseTestState.scenario = $case
    $rejected = $false
    try { & $releaseScript -ImageDigest $digest -Preview } catch { $rejected = $true }
    if (-not $rejected -or $global:azzuReleaseTestState.patches -ne 1) { throw "Unsafe scenario was not rejected before patch: $case" }
}
$rejected = $false
try { & $releaseScript -ImageDigest 'untrusted.example/bff:latest' -Preview } catch { $rejected = $true }
if (-not $rejected) { throw 'Untrusted or mutable image reference was accepted.' }
$global:LASTEXITCODE = 0 # Expected simulated kubectl failures must not fail GitHub's pwsh wrapper.
Write-Output 'PASS: 10 release gate scenarios; no cluster access or live mutations.'
