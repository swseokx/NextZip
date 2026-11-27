# Create a self-signed code signing certificate for NextZip test builds.
#
# The certificate goes to Cert:\CurrentUser\My only. It is NOT added to any
# trust store, so signatures made with it show "unknown publisher" and
# Get-AuthenticodeSignature reports UnknownError (untrusted root). That is
# expected for a test certificate; a purchased certificate replaces it.
#
# Usage:
#   .\new-test-cert.ps1            create (or reuse) and print the thumbprint
#   .\new-test-cert.ps1 -Remove    delete it again
param([switch]$Remove)

$ErrorActionPreference = 'Stop'
$subject = 'CN=NextZip Test Signing'
$existing = @(Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert |
    Where-Object { $_.Subject -eq $subject })

if ($Remove) {
    foreach ($c in $existing) {
        Write-Host "remove $($c.Thumbprint)"
        Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($c.Thumbprint)"
    }
    return
}

$valid = $existing | Where-Object { $_.NotAfter -gt (Get-Date).AddDays(7) } | Select-Object -First 1
if ($valid) {
    Write-Host "reuse $($valid.Thumbprint) (valid until $($valid.NotAfter))"
    return $valid.Thumbprint
}

$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $subject `
    -CertStoreLocation Cert:\CurrentUser\My -KeyAlgorithm RSA -KeyLength 3072 `
    -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(1) `
    -FriendlyName 'NextZip test code signing (not trusted)'
Write-Host "created $($cert.Thumbprint) (valid until $($cert.NotAfter))"
return $cert.Thumbprint
