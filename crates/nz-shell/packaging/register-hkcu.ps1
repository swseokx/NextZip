# Per-user registration of the NextZip context menu (classic menu on
# Windows 11 "Show more options", top-level menu on Windows 10).
#
# Writes only under HKCU\Software\Classes:
#   CLSID\{5870dc66-afb5-4e9c-ab2a-31f1bd5321d9}\InprocServer32
#   *\shell\NextZip           (ExplorerCommandHandler)
#   Directory\shell\NextZip   (ExplorerCommandHandler)
# It never changes file associations (no ProgID or default handler keys).
#
# Usage:
#   .\register-hkcu.ps1 -DllPath C:\path\to\nextzip_shell.dll
#   .\register-hkcu.ps1 -Unregister
#   add -WhatIf to print the changes without writing them
param(
    [string]$DllPath,
    [switch]$Unregister,
    [switch]$WhatIf
)

$ErrorActionPreference = 'Stop'
$clsid = '{5870dc66-afb5-4e9c-ab2a-31f1bd5321d9}'
$root = 'HKCU:\Software\Classes'
$keys = @(
    "$root\CLSID\$clsid",
    "$root\*\shell\NextZip",
    "$root\Directory\shell\NextZip"
)

if ($Unregister) {
    foreach ($k in $keys) {
        if (Test-Path -LiteralPath $k) {
            Write-Host "remove $k"
            if (-not $WhatIf) { Remove-Item -LiteralPath $k -Recurse -Force }
        }
    }
    Write-Host 'NextZip context menu removed (restart Explorer to refresh).'
    return
}

if (-not $DllPath) { throw 'Pass -DllPath with the full path of nextzip_shell.dll.' }
$dll = (Resolve-Path -LiteralPath $DllPath).Path
$exe = Join-Path (Split-Path $dll) 'nextzip.exe'
if (-not (Test-Path -LiteralPath $exe)) { throw "nextzip.exe must be next to the DLL: $exe" }

function Set-Value($key, $name, $value) {
    Write-Host "set $key [$name] = $value"
    if ($WhatIf) { return }
    if (-not (Test-Path -LiteralPath $key)) { New-Item -Path $key -Force | Out-Null }
    if ($name -eq '') {
        Set-Item -LiteralPath $key -Value $value
    } else {
        New-ItemProperty -LiteralPath $key -Name $name -Value $value -PropertyType String -Force | Out-Null
    }
}

Set-Value "$root\CLSID\$clsid" '' 'NextZip context menu'
Set-Value "$root\CLSID\$clsid\InprocServer32" '' $dll
Set-Value "$root\CLSID\$clsid\InprocServer32" 'ThreadingModel' 'Apartment'
foreach ($k in @("$root\*\shell\NextZip", "$root\Directory\shell\NextZip")) {
    Set-Value $k 'ExplorerCommandHandler' $clsid
    Set-Value $k 'MUIVerb' 'NextZip'
}
Write-Host 'Done. Restart Explorer (or sign out) to see the menu.'
