# Windows 11 top-level context menu through a signed sparse package.
#
# Requirements (done by the user, not by this script):
#   * Windows SDK (makeappx.exe, signtool.exe) on PATH
#   * a code signing certificate (.pfx) whose subject matches Publisher in
#     AppxManifest.xml, trusted on this PC (installing a certificate into
#     Trusted People / Root is a security setting: do it yourself)
#
# The package holds only AppxManifest.xml and logo.png; nextzip.exe and
# nextzip_shell.dll stay in -InstallDir (ExternalLocation).
# File associations are not changed.
#
# Usage:
#   .\register-sparse.ps1 -InstallDir C:\Apps\NextZip -Pfx cert.pfx -PfxPassword (Read-Host -AsSecureString)
#   .\register-sparse.ps1 -Unregister
param(
    [string]$InstallDir,
    [string]$Pfx,
    [securestring]$PfxPassword,
    [switch]$Unregister
)

$ErrorActionPreference = 'Stop'
$name = 'NextZip.ShellExtension'

if ($Unregister) {
    Get-AppxPackage -Name $name | ForEach-Object {
        Write-Host "remove $($_.PackageFullName)"
        Remove-AppxPackage -Package $_.PackageFullName
    }
    return
}

if (-not $InstallDir -or -not $Pfx) { throw 'Pass -InstallDir and -Pfx.' }
$dir = (Resolve-Path -LiteralPath $InstallDir).Path
foreach ($f in @('nextzip.exe', 'nextzip_shell.dll')) {
    if (-not (Test-Path -LiteralPath (Join-Path $dir $f))) { throw "missing $f in $dir" }
}

$work = Join-Path $env:TEMP ('nextzip-sparse-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'AppxManifest.xml') -Destination $work
$logo = Join-Path $PSScriptRoot 'logo.png'
if (Test-Path -LiteralPath $logo) {
    Copy-Item -LiteralPath $logo -Destination $work
} else {
    # 1x1 transparent PNG placeholder
    $png = [Convert]::FromBase64String('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==')
    [IO.File]::WriteAllBytes((Join-Path $work 'logo.png'), $png)
}

$msix = Join-Path $work 'NextZipShell.msix'
& makeappx.exe pack /d $work /p $msix /nv /o
if ($LASTEXITCODE -ne 0) { throw 'makeappx failed' }

$plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($PfxPassword))
& signtool.exe sign /fd SHA256 /f $Pfx /p $plain $msix
if ($LASTEXITCODE -ne 0) { throw 'signtool failed' }

Add-AppxPackage -Path $msix -ExternalLocation $dir
Write-Host 'Registered. Restart Explorer to see NextZip in the context menu.'
Remove-Item -LiteralPath $work -Recurse -Force
