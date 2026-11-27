# Build the signed per-user installer target\installer\nextzip-setup-<ver>.exe.
#
# 1. cargo build --release for nextzip.exe, nz.exe, nz-decode.exe, nextzip_shell.dll
#    and the SFX stub for x64 and ARM64 (nz-sfx-x64.exe, nz-sfx-arm64.exe;
#    needs: rustup target add aarch64-pc-windows-msvc, MSVC ARM64 build tools)
# 2. sign those six (if a certificate is available)
# 3. build nz-setup with NZ_SETUP_PAYLOAD pointing at the signed files
# 4. sign the installer and print each signature status
#
# Certificate: -Thumbprint <sha1>, otherwise the "CN=NextZip Test Signing"
# certificate from new-test-cert.ps1 in Cert:\CurrentUser\My. -NoSign skips
# signing. No timestamp server is contacted unless -TimestampUrl is given.
param(
    [string]$Thumbprint,
    [string]$TimestampUrl,
    [switch]$NoSign
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$out = Join-Path $root 'target\installer'
$stage = Join-Path $out 'payload'

function Find-SignTool {
    $kits = 'C:\Program Files (x86)\Windows Kits\10\bin'
    $found = Get-ChildItem -Path $kits -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -like '*\x64\*' } |
        Sort-Object FullName -Descending | Select-Object -First 1
    if (-not $found) { throw 'signtool.exe not found (install the Windows SDK).' }
    return $found.FullName
}

function Invoke-Sign([string]$file) {
    if ($NoSign) { return }
    $signArgs = @('sign', '/fd', 'SHA256', '/sha1', $SignThumbprint, '/s', 'My')
    if ($TimestampUrl) { $signArgs += @('/tr', $TimestampUrl, '/td', 'SHA256') }
    $signArgs += $file
    & $SignToolPath @signArgs | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "signtool failed for $file" }
}

if (-not $NoSign) {
    $SignToolPath = Find-SignTool
    if (-not $Thumbprint) {
        $c = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert |
            Where-Object { $_.Subject -eq 'CN=NextZip Test Signing' -and $_.NotAfter -gt (Get-Date) } |
            Select-Object -First 1
        if (-not $c) { throw 'No signing certificate. Run new-test-cert.ps1, pass -Thumbprint, or use -NoSign.' }
        $Thumbprint = $c.Thumbprint
    }
    $SignThumbprint = $Thumbprint
    Write-Host "signing with $Thumbprint"
}

Push-Location $root
try {
    cargo build --release -p nz-gui -p nz-cli -p nz-shell
    if ($LASTEXITCODE -ne 0) { throw 'cargo build failed' }
    # Isolated decoder process for legacy and rare formats (spec 9).
    cargo build --release -p nz-archive --bin nz-decode
    if ($LASTEXITCODE -ne 0) { throw 'cargo build of nz-decode failed' }
    # Self-extractor stubs; nz c -fmt:sfx-x64 / sfx-arm64 prepends them.
    $stubs = @{ 'x86_64-pc-windows-msvc' = 'nz-sfx-x64.exe'; 'aarch64-pc-windows-msvc' = 'nz-sfx-arm64.exe' }
    foreach ($t in $stubs.Keys) {
        cargo build --release -p nz-sfx --bin nz-sfx --target $t
        if ($LASTEXITCODE -ne 0) { throw "cargo build of nz-sfx for $t failed" }
    }

    New-Item -ItemType Directory -Force $stage | Out-Null
    foreach ($f in @('nextzip.exe', 'nz.exe', 'nz-decode.exe', 'nextzip_shell.dll')) {
        Copy-Item -Force (Join-Path $root "target\release\$f") (Join-Path $stage $f)
        Invoke-Sign (Join-Path $stage $f)
    }
    foreach ($t in $stubs.Keys) {
        $dst = Join-Path $stage $stubs[$t]
        Copy-Item -Force (Join-Path $root "target\$t\release\nz-sfx.exe") $dst
        Invoke-Sign $dst
    }

    $env:NZ_SETUP_PAYLOAD = $stage
    try {
        cargo build --release -p nz-setup
        if ($LASTEXITCODE -ne 0) { throw 'cargo build -p nz-setup failed' }
    } finally {
        Remove-Item Env:\NZ_SETUP_PAYLOAD
    }

    $meta = cargo metadata --format-version 1 --no-deps | ConvertFrom-Json
    $ver = ($meta.packages | Where-Object { $_.name -eq 'nz-setup' }).version
    $setup = Join-Path $out "nextzip-setup-$ver.exe"
    Copy-Item -Force (Join-Path $root 'target\release\nextzip-setup.exe') $setup
    Invoke-Sign $setup

    Write-Host ''
    foreach ($f in @((Get-ChildItem $stage -File).FullName + $setup)) {
        $s = Get-AuthenticodeSignature -LiteralPath $f
        $who = if ($s.SignerCertificate) { $s.SignerCertificate.Subject } else { '-' }
        Write-Host ('{0,-24} {1,-14} {2}' -f (Split-Path $f -Leaf), $s.Status, $who)
    }
    $h = Get-FileHash -Algorithm SHA256 -LiteralPath $setup
    Write-Host ''
    Write-Host "installer: $setup"
    Write-Host "size:      $((Get-Item $setup).Length) bytes"
    Write-Host "sha256:    $($h.Hash)"
} finally {
    Pop-Location
}
