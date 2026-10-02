#requires -Version 7.0
[CmdletBinding()]
param(
    [switch] $CreatePendingRequest,
    [string] $OutputDirectory = (Join-Path $PSScriptRoot '../../artifacts/mapping-csr')
)

$ErrorActionPreference = 'Stop'
$subscription = '8466fec9-2d75-4f1b-9bd7-52ea3e024ab9'
$vault = 'kv-azzu-web-dev-8466fe'
$certificateName = 'azzu-web-bff-dev-mapping-mtls'
$expectedPrivateAddress = '10.20.5.22'
$policyPath = Join-Path $PSScriptRoot 'mapping-client-policy.json'
$policy = Get-Content -LiteralPath $policyPath -Raw | ConvertFrom-Json
if ($policy.issuerParameters.name -ne 'Unknown' -or $policy.keyProperties.reuseKey -ne $false -or
    $policy.x509CertificateProperties.subject -ne 'CN=azzu-web-bff-dev' -or
    @($policy.x509CertificateProperties.ekus).Count -ne 1 -or
    $policy.x509CertificateProperties.ekus[0] -ne '1.3.6.1.5.5.7.3.2') {
    throw 'Certificate policy does not match the approved Mapping caller.'
}

$addresses = @(Resolve-DnsName "$vault.vault.azure.net" -Type A |
    Where-Object Type -eq 'A' | Select-Object -ExpandProperty IPAddress)
[pscustomobject]@{
    Vault = $vault; Certificate = $certificateName; ResolvedAddresses = $addresses
    ExpectedPrivateAddress = $expectedPrivateAddress; CreateRequested = [bool]$CreatePendingRequest
    Policy = $policyPath
}
if (-not $CreatePendingRequest) {
    Write-Output 'Preview only. No Azure changes and no CSR/key generation.'
    return
}
if ($addresses.Count -ne 1 -or $addresses[0] -ne $expectedPrivateAddress) {
    throw 'Private DNS/access prerequisite not met. Do not open the vault firewall or substitute a local private key.'
}
if (Test-Path -LiteralPath (Join-Path $OutputDirectory 'azzu-web-bff-dev.csr')) {
    throw 'CSR output already exists. Do not overwrite it or create a replacement key.'
}

$vaultJson = & az keyvault show --name $vault --subscription $subscription --only-show-errors -o json
if ($LASTEXITCODE -ne 0) { throw 'Vault metadata preflight failed.' }
$vaultMetadata = $vaultJson | ConvertFrom-Json
if ($vaultMetadata.properties.publicNetworkAccess -ne 'Disabled') {
    throw 'The vault must remain private.'
}

# Read access must work before generating anything. This also stops on missing RBAC.
$listJson = & az keyvault certificate list --vault-name $vault --subscription $subscription --only-show-errors -o json
if ($LASTEXITCODE -ne 0) { throw 'Certificate metadata access failed. Request narrowly scoped access; do not broaden RBAC automatically.' }
$existing = @($listJson | ConvertFrom-Json)
if ($existing | Where-Object { $_.id -match "/certificates/$certificateName(?:/|$)" }) {
    throw 'Certificate already exists. Inspect its pending request rather than creating a new version.'
}
$pendingResult = & az keyvault certificate pending show --vault-name $vault --name $certificateName --subscription $subscription --only-show-errors -o json 2>&1
if ($LASTEXITCODE -eq 0) {
    throw 'A pending request already exists. Retrieve that public CSR separately; do not generate another key.'
}
if (($pendingResult -join "`n") -notmatch 'CertificateNotFound|PendingCertificateNotFound') {
    throw 'Could not rule out an existing pending request. No creation attempted.'
}

# Only this specific new object is created; the key stays in Key Vault.
# Exportable is required for conventional TLS runtime use, not permission to share the key.
$operationJson = & az keyvault certificate create --vault-name $vault --name $certificateName `
    --policy "@$policyPath" --subscription $subscription --only-show-errors `
    --query '{id:id,status:status,csr:csr}' -o json
if ($LASTEXITCODE -ne 0) { throw 'CSR creation failed. Inspect the pending operation before retrying; never auto-delete it.' }
$operation = $operationJson | ConvertFrom-Json
if ([string]::IsNullOrWhiteSpace($operation.csr)) {
    throw 'Azure returned no public CSR. Inspect the pending operation; do not create a second key.'
}
$csrBytes = [Convert]::FromBase64String($operation.csr)
$csrPem = "-----BEGIN CERTIFICATE REQUEST-----`n" +
    [Convert]::ToBase64String($csrBytes, [Base64FormattingOptions]::InsertLineBreaks) +
    "`n-----END CERTIFICATE REQUEST-----`n"
[System.IO.Directory]::CreateDirectory([System.IO.Path]::GetFullPath($OutputDirectory)) | Out-Null
[System.IO.File]::WriteAllText((Join-Path $OutputDirectory 'azzu-web-bff-dev.csr'), $csrPem)
Write-Output "Public CSR saved in $OutputDirectory. Send only this CSR to Aldo. No private key was downloaded."
