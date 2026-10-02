<#[READ ONLY] Checks public OIDC metadata and app configuration; never requests tokens or writes Azure.#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$tenant = 'db24bd50-f509-4173-9375-d30840ec6f39'
$client = 'cecb6910-e653-4129-8376-c044209a751e'
$application = '81eff91b-a991-4f09-a56c-f42fa2e230aa'
$flow = '417fdec2-4cb1-4721-ac39-48886c492a88'
$origin = 'https://banca.azzu.tech'
$issuer = "https://$tenant.ciamlogin.com/$tenant/v2.0"
$checks = [System.Collections.Generic.List[object]]::new()
function Add-Check([string]$Name, [bool]$Pass, [string]$Detail) {
    $checks.Add([pscustomobject]@{ Check = $Name; Status = $(if ($Pass) { 'PASS' } else { 'BLOCKED' }); Detail = $Detail })
}
function Read-Graph([string]$Path) {
    # No query separators: avoids Windows az.cmd shell parsing of ampersands.
    $json = & az rest --method GET --url "https://graph.microsoft.com/v1.0/$Path" --subscription $tenant --only-show-errors -o json 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'Graph read failed; verify tenant login and read permissions.' }
    return ($json | Out-String | ConvertFrom-Json)
}
try {
    $app = Read-Graph "applications/$application"
    Add-Check 'Application identity' ($app.appId -eq $client) 'Expected BFF registration, not Mobile.'
    Add-Check 'Confidential single-tenant app' ($app.signInAudience -eq 'AzureADMyOrg' -and -not $app.isFallbackPublicClient -and @($app.spa.redirectUris).Count -eq 0) 'Web BFF; no SPA/public-client token flow.'
    Add-Check 'Implicit flow disabled' (-not $app.web.implicitGrantSettings.enableAccessTokenIssuance -and -not $app.web.implicitGrantSettings.enableIdTokenIssuance) 'Authorization Code + PKCE expected.'
    foreach ($path in @('/api/v1/auth/callback', '/api/v1/auth/signout-callback')) {
        Add-Check "Registered $path" ($app.web.redirectUris -contains "$origin$path") 'Registration alone does not prove reachable callback or implemented handler.'
    }
    $apps = Read-Graph "identity/authenticationEventsFlows/$flow/conditions/applications/includeApplications"
    Add-Check 'BFF assigned to user flow' ($apps.value.appId -contains $client) 'Read only; existing pilot membership preserved.'
    $federation = Read-Graph "applications/$application/federatedIdentityCredentials"
    $now = [DateTimeOffset]::UtcNow
    $credentials = @($app.passwordCredentials) + @($app.keyCredentials)
    $active = @($credentials | Where-Object { $_ -and [DateTimeOffset]$_.startDateTime -le $now -and [DateTimeOffset]$_.endDateTime -gt $now })
    Add-Check 'Active OIDC credential metadata' ($active.Count -gt 0 -or @($federation.value).Count -gt 0) 'Metadata only; presence does not prove runtime loading or token exchange.'
} catch {
    Add-Check 'Graph inspection' $false 'Read failed; no credentials, response bodies or identities printed.'
}
try {
    $metadata = Invoke-RestMethod -Uri "$issuer/.well-known/openid-configuration" -TimeoutSec 30
    Add-Check 'Discovery issuer' ($metadata.issuer -ceq $issuer) 'Exact issuer used by Mapping.'
    $validEndpoints = $true
    foreach ($name in @('authorization_endpoint', 'token_endpoint', 'jwks_uri', 'end_session_endpoint')) {
        $uri = [Uri]$metadata.$name
        if (-not $uri.IsAbsoluteUri -or $uri.Scheme -ne 'https' -or $uri.Host -ne "$tenant.ciamlogin.com") { $validEndpoints = $false }
    }
    Add-Check 'OIDC HTTPS endpoints' $validEndpoints 'Discovery, not an interactive login or logout test.'
    Add-Check 'Certificate client assertion advertised' ($metadata.token_endpoint_auth_methods_supported -contains 'private_key_jwt') 'Requires separate registered OIDC certificate and adapter; never reuse Mapping mTLS.'
} catch {
    Add-Check 'OIDC discovery' $false 'Discovery unavailable or malformed; no provider body logged.'
}
$checks | Format-Table -AutoSize -Wrap
Write-Output 'No Azure writes, credential creation, deployment or authentication challenge performed.'
if (@($checks | Where-Object Status -eq 'BLOCKED').Count -gt 0) { exit 2 }
exit 0
