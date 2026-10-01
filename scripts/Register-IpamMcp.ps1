<#
.SYNOPSIS
    Adds the IPAM MCP server to Claude Desktop's config, safely, while Claude Desktop is closed.

.DESCRIPTION
    Purpose      : Claude Desktop keeps its config in memory and rewrites claude_desktop_config.json
                   while it runs, which drops edits made underneath it. This script waits until every
                   Claude Desktop process has exited, backs up the config, adds mcpServers.ipam (keeping
                   everything else), checks the result is valid JSON, and optionally starts Claude again.
    Author       : Craig McDonald (Technical Architect), drafted with Claude
    Date         : 2026-10-01
    Supported OS : Windows 10/11 (PowerShell 5.1 or 7+)
    Dependencies : The IPAM MCP server installed in <repo>\mcp\.venv (see mcp\README.md)

    Run it from a normal PowerShell window (not from inside Claude), then quit Claude Desktop
    from the system tray (right-click the Claude icon > Quit).

.PARAMETER NoRestart
    Don't start Claude Desktop again afterwards.

.PARAMETER TimeoutMinutes
    How long to wait for Claude Desktop to close. Default 10.

.EXAMPLE
    .\scripts\Register-IpamMcp.ps1
#>
[CmdletBinding()]
param(
    [switch]$NoRestart,
    [ValidateRange(1, 60)]
    [int]$TimeoutMinutes = 10
)

$ErrorActionPreference = 'Stop'

try {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    $exe = Join-Path $repoRoot 'mcp\.venv\Scripts\ipam-mcp.exe'
    $config = Join-Path $env:APPDATA 'Claude\claude_desktop_config.json'

    if (-not (Test-Path $exe)) { throw "IPAM MCP server not installed at $exe (see mcp\README.md)" }
    if (-not (Test-Path $config)) { throw "Claude Desktop config not found at $config" }

    # Only the Desktop app counts; the Claude Code CLI is also claude.exe but lives elsewhere.
    function Get-ClaudeDesktop {
        Get-Process -Name 'claude' -ErrorAction SilentlyContinue |
            Where-Object { $_.Path -and ($_.Path -like '*\WindowsApps\Claude_*' -or $_.Path -like '*\AnthropicClaude\*') }
    }
    # Store (MSIX) installs are started through their app ID, not the exe path.
    $startApp = Get-StartApps -Name 'Claude' -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'Claude' } | Select-Object -First 1
    $wasRunning = [bool](Get-ClaudeDesktop)

    if (Get-ClaudeDesktop) {
        Write-Host '[..] Waiting for Claude Desktop to close. Quit it from the system tray: right-click the Claude icon > Quit.' -ForegroundColor Cyan
        $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
        while (Get-ClaudeDesktop) {
            if ((Get-Date) -gt $deadline) { throw "Claude Desktop is still running after $TimeoutMinutes minutes; nothing was changed." }
            Start-Sleep -Seconds 2
        }
        Start-Sleep -Seconds 2   # let it finish its last write
    }
    Write-Host '[OK] Claude Desktop is closed' -ForegroundColor Green

    $backup = "$config.bak-$(Get-Date -Format yyyyMMdd-HHmmss)"
    Copy-Item $config $backup

    $json = Get-Content -Raw $config | ConvertFrom-Json
    if (-not $json.PSObject.Properties['mcpServers']) {
        $json | Add-Member -NotePropertyName 'mcpServers' -NotePropertyValue ([pscustomobject]@{})
    }
    $entry = [pscustomobject]@{ command = $exe }
    if ($json.mcpServers.PSObject.Properties['ipam']) { $json.mcpServers.ipam = $entry }
    else { $json.mcpServers | Add-Member -NotePropertyName 'ipam' -NotePropertyValue $entry }

    $text = $json | ConvertTo-Json -Depth 50
    $null = $text | ConvertFrom-Json   # refuse to write anything that isn't valid JSON
    [System.IO.File]::WriteAllText($config, $text + "`n", (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "[OK] Added mcpServers.ipam to $config (backup: $backup)" -ForegroundColor Green

    if (-not $NoRestart -and $startApp) {
        Start-Process "shell:AppsFolder\$($startApp.AppID)"
        Write-Host '[OK] Started Claude Desktop. In a new chat, the ipam tools appear under the tools (connector) menu.' -ForegroundColor Green
    }
    elseif (-not $NoRestart) {
        Write-Host '[..] Start Claude Desktop from the Start menu.' -ForegroundColor Cyan
    }
}
catch {
    Write-Error "Couldn't register the IPAM MCP server: $($_.Exception.Message)"
    exit 1
}
