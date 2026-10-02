[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[a-z0-9][a-z0-9_.-]{0,127}$')]
    [string] $ImageTag,
    [string] $OutputDirectory = 'artifacts/container'
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$evidenceDirectory = [IO.Path]::GetFullPath((Join-Path $repoRoot $OutputDirectory))
if (-not $evidenceDirectory.StartsWith($repoRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Container evidence must stay inside this repository.'
}
$archivePath = Join-Path $evidenceDirectory 'azzu-web-bff.tar.gz'
if (Test-Path -LiteralPath $archivePath) {
    throw 'Container archive already exists. Preserve it and choose another OutputDirectory.'
}
New-Item -ItemType Directory -Path (Split-Path $archivePath -Parent) -Force | Out-Null
Push-Location $repoRoot
try {
    & dotnet publish src/Azzu.WebBff.Api/Azzu.WebBff.Api.csproj `
        --configuration Release --os linux --arch x64 --self-contained false `
        /t:PublishContainer -p:PublishProfile=Container `
        "-p:ContainerImageTag=$ImageTag" "-p:ContainerArchiveOutputPath=$archivePath"
    if ($LASTEXITCODE -ne 0) { throw 'Container publish failed.' }
    if (-not (Test-Path -LiteralPath $archivePath)) { throw 'Container archive was not produced.' }
    Get-FileHash -LiteralPath $archivePath -Algorithm SHA256
} finally {
    Pop-Location
}
