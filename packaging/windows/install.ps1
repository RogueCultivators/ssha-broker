#Requires -Version 5.1
<#
  ssha for Windows - per-user install / upgrade.

  Installs two files next to each other and sets up shortcuts:

    ssha.exe      console build: the CLI and the MCP server
    ssha-ui.exe   window build: opens the editor with no console window

  It adds the folder to the user PATH, creates Start Menu and desktop
  shortcuts, writes a starter config when there is none, and can start ssha
  automatically when you log in. No administrator rights are needed.

  Usage, from the folder you extracted:

      powershell -ExecutionPolicy Bypass -File .\install.ps1
      powershell -ExecutionPolicy Bypass -File .\install.ps1 -Autostart both
      powershell -ExecutionPolicy Bypass -File .\install.ps1 -Autostart none -NoDesktop

  Options:
    -InstallDir DIR  target folder (default %LOCALAPPDATA%\Programs\ssha)
    -Autostart X     ui | mcp | both | none        (default ui)
    -McpPort N       MCP http port for mcp/both    (default 8765)
    -NoPath          do not touch the user PATH
    -NoStartMenu     do not create the Start Menu shortcut
    -NoDesktop       do not create the desktop shortcut
    -NoConfig        do not write a starter config
    -NoKill          do not stop a running ssha before replacing the files
#>
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'Programs\ssha'),
    [ValidateSet('ui', 'mcp', 'both', 'none')][string]$Autostart = 'ui',
    [int]$McpPort = 8765,
    [switch]$NoPath,
    [switch]$NoStartMenu,
    [switch]$NoDesktop,
    [switch]$NoConfig,
    [switch]$NoKill
)

$ErrorActionPreference = 'Stop'

function Say($m) { Write-Host ''; Write-Host "== $m" -ForegroundColor Cyan }
function Note($m) { Write-Host "   $m" }

function New-Shortcut {
    param([string]$Path, [string]$Target, [string]$Arguments, [string]$Icon, [string]$WorkDir)
    $shell = New-Object -ComObject WScript.Shell
    $link = $shell.CreateShortcut($Path)
    $link.TargetPath = $Target
    if ($Arguments) { $link.Arguments = $Arguments }
    if ($Icon) { $link.IconLocation = $Icon }
    if ($WorkDir) { $link.WorkingDirectory = $WorkDir }
    $link.Save()
}

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$srcExe = Join-Path $here 'ssha.exe'
$srcUi = Join-Path $here 'ssha-ui.exe'
if (-not (Test-Path $srcExe)) { throw "ssha.exe was not found next to this script ($here)" }
if (-not (Test-Path $srcUi)) { $srcUi = $srcExe }   # package with a single exe

# Stop a running copy, otherwise Windows holds the file and the copy fails.
if (-not $NoKill) {
    Get-Process -Name 'ssha', 'ssha-ui' -ErrorAction SilentlyContinue |
        Where-Object { try { $_.Path -and $_.Path.StartsWith($InstallDir, [StringComparison]::OrdinalIgnoreCase) } catch { $false } } |
        ForEach-Object {
            Note "stopping $($_.Path)"
            $_ | Stop-Process -Force
        }
}

Say "installing into $InstallDir"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item -Force $srcExe (Join-Path $InstallDir 'ssha.exe')
Copy-Item -Force $srcUi (Join-Path $InstallDir 'ssha-ui.exe')
$exe = Join-Path $InstallDir 'ssha.exe'
$ui = Join-Path $InstallDir 'ssha-ui.exe'
Note $ui
& $exe version | ForEach-Object { Note $_ }

if (-not $NoPath) {
    $current = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not $current) { $current = '' }
    $parts = @($current -split ';' | Where-Object { $_ -ne '' })
    if ($parts -notcontains $InstallDir) {
        [Environment]::SetEnvironmentVariable('Path', (@($parts) + $InstallDir) -join ';', 'User')
        Note "added $InstallDir to the user PATH (open a new terminal to pick it up)"
    }
    else {
        Note 'the user PATH already contains the install folder'
    }
}

$uiIcon = "$ui,0"
if (-not $NoStartMenu) {
    $startMenu = Join-Path ([Environment]::GetFolderPath('Programs')) 'ssha.lnk'
    New-Shortcut -Path $startMenu -Target $ui -Arguments 'ui' -Icon $uiIcon -WorkDir $env:USERPROFILE
    Note "Start Menu: $startMenu"
}
if (-not $NoDesktop) {
    $desktop = Join-Path ([Environment]::GetFolderPath('Desktop')) 'ssha.lnk'
    New-Shortcut -Path $desktop -Target $ui -Arguments 'ui' -Icon $uiIcon -WorkDir $env:USERPROFILE
    Note "Desktop: $desktop"
}

$configPath = Join-Path $env:USERPROFILE '.config\ssha\config.yaml'
if (Test-Path $configPath) {
    Note "config: $configPath (kept)"
}
elseif (-not $NoConfig) {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $configPath) | Out-Null
    & $exe init --out $configPath | Out-Null
    Note "config: $configPath (edit the hosts section)"
}

# Autostart lives in the Startup folder: visible, and removed by uninstall.ps1.
$startup = [Environment]::GetFolderPath('Startup')
$uiLink = Join-Path $startup 'ssha ui.lnk'
$mcpLink = Join-Path $startup 'ssha mcp.lnk'
Remove-Item -Force -ErrorAction SilentlyContinue $uiLink, $mcpLink
switch ($Autostart) {
    'ui' {
        New-Shortcut -Path $uiLink -Target $ui -Arguments 'ui' -Icon $uiIcon -WorkDir $env:USERPROFILE
        Note 'autostart: the ssha window opens at logon'
    }
    'mcp' {
        New-Shortcut -Path $mcpLink -Target $ui -Arguments "mcp --http 127.0.0.1:$McpPort" -Icon $uiIcon -WorkDir $env:USERPROFILE
        Note "autostart: MCP on http://127.0.0.1:$McpPort at logon (no window)"
    }
    'both' {
        New-Shortcut -Path $uiLink -Target $ui -Arguments 'ui' -Icon $uiIcon -WorkDir $env:USERPROFILE
        New-Shortcut -Path $mcpLink -Target $ui -Arguments "mcp --http 127.0.0.1:$McpPort" -Icon $uiIcon -WorkDir $env:USERPROFILE
        Note "autostart: window + MCP on http://127.0.0.1:$McpPort at logon"
    }
    'none' {
        Note 'autostart: off'
    }
}

Say 'done'
Note 'open the window from the Start Menu shortcut "ssha" (or run: ssha-ui ui)'
Note 'command line in a new terminal: ssha hosts list'
