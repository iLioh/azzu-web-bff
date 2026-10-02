param([Parameter(Mandatory)][ValidateSet('Protect','Unprotect','Sid')][string]$Mode)
$ErrorActionPreference='Stop'
try {
    if ($Mode -eq 'Sid') {
        [Console]::Out.Write([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
        exit 0
    }
    Add-Type -AssemblyName System.Security
    $value=[Console]::In.ReadToEnd().Trim()
    $entropy=[Text.Encoding]::UTF8.GetBytes('AZZU-ACME-ACCOUNT-V1')
    $inputBytes=[Convert]::FromBase64String($value)
    if ($Mode -eq 'Protect') {
        $outputBytes=[Security.Cryptography.ProtectedData]::Protect($inputBytes,$entropy,[Security.Cryptography.DataProtectionScope]::CurrentUser)
    } else {
        $outputBytes=[Security.Cryptography.ProtectedData]::Unprotect($inputBytes,$entropy,[Security.Cryptography.DataProtectionScope]::CurrentUser)
    }
    [Console]::Out.Write([Convert]::ToBase64String($outputBytes))
    [Array]::Clear($inputBytes,0,$inputBytes.Length)
    [Array]::Clear($outputBytes,0,$outputBytes.Length)
} catch {
    [Console]::Error.Write('DPAPI operation failed; sensitive input suppressed.')
    exit 1
}
