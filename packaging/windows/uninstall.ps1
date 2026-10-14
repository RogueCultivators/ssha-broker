#Requires -Version 5.1
<#
  ssha for Windows - uninstall.

  Removes the install folder, the shortcuts and the autostart entries that
  install.ps1 created. The config, the sealed secrets and the audit log are
  kept, because they are yours: pass -Purge to delete those too.

  Usage:
      powershell -ExecutionPolicy Bypass -File .\uninstall.ps1
      powershell -ExecutionPolicy Bypass -File .\uninstall.ps1 -Purge
#>
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'Programs\ssha'),
    [switch]$Purge,
    [switch]$NoPath
)

$ErrorActionPreference = 'Stop'

function Say($m) { Write-Host ''; Write-Host "== $m" -ForegroundColor Cyan }
function Note($m) { Write-Host "   $m" }

Say 'stopping a running ssha'
Get-Process -Name 'ssha', 'ssha-ui' -ErrorAction SilentlyContinue |
    Where-Object { try { $_.Path -and $_.Path.StartsWith($InstallDir, [StringComparison]::OrdinalIgnoreCase) } catch { $false } } |
    ForEach-Object {
        Note "stopping $($_.Path)"
        $_ | Stop-Process -Force
    }

Say 'removing the shortcuts'
$startup = [Environment]::GetFolderPath('Startup')
$links = @(
    (Join-Path $startup 'ssha ui.lnk'),
    (Join-Path $startup 'ssha mcp.lnk'),
    (Join-Path ([Environment]::GetFolderPath('Programs')) 'ssha.lnk'),
    (Join-Path ([Environment]::GetFolderPath('Desktop')) 'ssha.lnk')
)
foreach ($link in $links) {
    if (Test-Path $link) {
        Remove-Item -Force $link
        Note $link
    }
}

if (-not $NoPath) {
    $current = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($current) {
        $parts = @($current -split ';' | Where-Object { $_ -ne '' -and $_ -ne $InstallDir })
        if ($parts.Count -ne @($current -split ';' | Where-Object { $_ -ne '' }).Count) {
            [Environment]::SetEnvironmentVariable('Path', ($parts -join ';'), 'User')
            Note "removed $InstallDir from the user PATH"
        }
    }
}

Say 'removing the install folder'
if (Test-Path $InstallDir) {
    Remove-Item -Recurse -Force $InstallDir
    Note $InstallDir
}

if ($Purge) {
    Say 'removing the config, secrets and audit log'
    $keep = @(
        (Join-Path $env:USERPROFILE '.config\ssha'),
        (Join-Path $env:USERPROFILE '.local\share\ssha')
    )
    foreach ($dir in $keep) {
        if (Test-Path $dir) {
            Remove-Item -Recurse -Force $dir
            Note $dir
        }
    }
}
else {
    Say 'kept'
    Note 'config + secrets: %USERPROFILE%\.config\ssha'
    Note 'audit log:         %USERPROFILE%\.local\share\ssha'
    Note 'delete those by hand, or re-run with -Purge'
}

Say 'done'
