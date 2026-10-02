[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^acrneobancoazzu8466fe\.azurecr\.io/azzu-web-bff@sha256:[0-9a-f]{64}$')]
    [string] $ImageDigest,
    [switch] $Preview
)

$ErrorActionPreference = 'Stop'
$namespace = 'azzu-web-dev'
$deploymentName = 'azzu-web-bff'
function Read-KubernetesObject([string[]] $Arguments) {
    $result = & kubectl @Arguments
    if ($LASTEXITCODE -ne 0) { throw 'Required Kubernetes resource could not be read. No bootstrap or permission fallback is allowed.' }
    return (($result -join "`n") | ConvertFrom-Json)
}

# Release only: never creates a namespace, Service, credentials, policies or RBAC.
$deployment = Read-KubernetesObject @('get', 'deployment', $deploymentName, '-n', $namespace, '-o', 'json')
$pod = $deployment.spec.template.spec
$containers = @($pod.containers)
if ($deployment.metadata.namespace -ne $namespace -or $deployment.metadata.name -ne $deploymentName -or
    $deployment.spec.replicas -ne 1 -or $deployment.spec.strategy.type -ne 'Recreate' -or
    $containers.Count -ne 1 -or $containers[0].name -ne 'web-bff' -or
    $pod.serviceAccountName -ne 'azzu-web-bff' -or $pod.automountServiceAccountToken -ne $false -or
    $deployment.spec.template.metadata.labels.'azure.workload.identity/use' -ne 'true') {
    throw 'Existing deployment is not the reviewed single-replica, Workload Identity DEV baseline.'
}
$container = $containers[0]
if ($pod.hostNetwork -eq $true -or $pod.hostPID -eq $true -or $pod.hostIPC -eq $true -or
    $pod.securityContext.runAsNonRoot -ne $true -or $pod.securityContext.seccompProfile.type -ne 'RuntimeDefault' -or
    $container.securityContext.readOnlyRootFilesystem -ne $true -or
    $container.securityContext.allowPrivilegeEscalation -ne $false -or $container.securityContext.privileged -eq $true -or
    @($container.securityContext.capabilities.drop) -notcontains 'ALL' -or
    $container.readinessProbe.httpGet.scheme -ne 'HTTPS' -or $container.readinessProbe.httpGet.port -ne 8443 -or
    $container.readinessProbe.httpGet.path -ne '/health/ready' -or
    $container.livenessProbe.httpGet.scheme -ne 'HTTPS' -or $container.livenessProbe.httpGet.port -ne 8443) {
    throw 'Existing deployment lacks reviewed runtime security or HTTPS probes.'
}
$service = Read-KubernetesObject @('get', 'service', $deploymentName, '-n', $namespace, '-o', 'json')
if ($service.spec.type -ne 'LoadBalancer' -or
    $service.metadata.annotations.'service.beta.kubernetes.io/azure-load-balancer-internal' -ne 'true' -or
    @($service.status.loadBalancer.ingress).Count -ne 1 -or $service.status.loadBalancer.ingress[0].ip -ne '10.20.0.7' -or
    @($service.spec.ports).Count -ne 1 -or $service.spec.ports[0].port -ne 443 -or $service.spec.ports[0].targetPort -ne 8443) {
    throw 'Private Service/TLS bootstrap is not ready. Release refuses to create or change it.'
}
$autoscalers = Read-KubernetesObject @('get', 'hpa', '-n', $namespace, '-o', 'json')
if (@($autoscalers.items | Where-Object { $_.spec.scaleTargetRef.name -eq $deploymentName }).Count -ne 0) {
    throw 'HPA must remain disabled until sessions and Data Protection are distributed.'
}
$patch = ConvertTo-Json -Compress -Depth 5 -InputObject @(
    @{ op = 'test'; path = '/metadata/resourceVersion'; value = $deployment.metadata.resourceVersion },
    @{ op = 'test'; path = '/spec/template/spec/containers/0/name'; value = 'web-bff' },
    @{ op = 'replace'; path = '/spec/template/spec/containers/0/image'; value = $ImageDigest }
)
$arguments = @('patch', 'deployment', $deploymentName, '-n', $namespace, '--type=json', '--patch', $patch, '-o', 'name')
if ($Preview) { $arguments += '--dry-run=server' }
Write-Output "Previous image: $($container.image)"
Write-Output "Requested image: $ImageDigest; preview: $Preview"
& kubectl @arguments
if ($LASTEXITCODE -ne 0) { throw 'Image-only patch rejected. Stop for review; no automatic permission escalation or rollback.' }
if (-not $Preview) {
    & kubectl rollout status "deployment/$deploymentName" -n $namespace --timeout=300s
    if ($LASTEXITCODE -ne 0) { throw 'Rollout failed. Review health evidence and explicitly approve restoring the previous image digest.' }
}
