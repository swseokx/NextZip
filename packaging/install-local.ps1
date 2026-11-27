# Build the signed installer and install NextZip for the current user (quiet).
# Used by Depot: `ship nextzip pc`.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

& (Join-Path $PSScriptRoot 'build-installer.ps1')
if (-not $?) { throw 'installer build failed' }

$setup = Get-ChildItem (Join-Path $root 'target\installer') -Filter 'nextzip-setup-*.exe' |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $setup) { throw 'installer not found under target\installer' }

Write-Host "installing $($setup.Name)"
$p = Start-Process -FilePath $setup.FullName -ArgumentList '/quiet' -Wait -PassThru
if ($p.ExitCode -ne 0) { throw "installer exited with code $($p.ExitCode)" }
Write-Host 'installed'
