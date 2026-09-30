<#
.SYNOPSIS
    Creates the .env file for the NEXTDC IPAM POC with a random database password and development API key.

.DESCRIPTION
    Purpose      : One-time local set-up for the Docker Compose stack.
    Author       : Craig McDonald (Technical Architect), drafted with Claude
    Date         : 2026-09-30
    Supported OS : Windows 10/11, Windows Server 2019+ (PowerShell 5.1 or 7+)
    Dependencies : None

    The .env file is git-ignored. The API key it contains is printed once so you can
    copy it into Swagger (Authorize) or a client; it isn't written anywhere else.
    Re-running the script leaves an existing .env alone unless -Force is given.

.PARAMETER Force
    Overwrite an existing .env. The database volume keeps the old password, so
    also run 'docker compose down -v' (which deletes all POC data) if you do this.

.PARAMETER Port
    Host port for the API (bound to 127.0.0.1 only). Default 8820.

.EXAMPLE
    .\scripts\Initialize-IpamEnv.ps1
#>
[CmdletBinding()]
param(
    [switch]$Force,
    [ValidateRange(1024, 65535)]
    [int]$Port = 8820
)

$ErrorActionPreference = 'Stop'

function New-RandomToken {
    param([int]$Bytes = 32)
    $buffer = New-Object byte[] $Bytes
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($buffer)
    # URL-safe base64 without padding, so the value is safe in URLs, headers and .env files
    return ([Convert]::ToBase64String($buffer)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

try {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    $envPath = Join-Path $repoRoot '.env'

    if ((Test-Path $envPath) -and -not $Force) {
        Write-Host "[SKIP] $envPath already exists. Use -Force to replace it." -ForegroundColor Yellow
        return
    }

    # Key format ipam_<8 hex prefix>_<secret> (spec §10.4)
    $prefixBytes = New-Object byte[] 4
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($prefixBytes)
    $prefix = -join ($prefixBytes | ForEach-Object { $_.ToString('x2') })
    $apiKey = "ipam_${prefix}_$(New-RandomToken -Bytes 32)"
    $dbPassword = New-RandomToken -Bytes 24

    $content = @(
        '# NEXTDC IPAM POC - local development secrets. Never commit this file.'
        "POSTGRES_PASSWORD=$dbPassword"
        "IPAM_BOOTSTRAP_API_KEY=$apiKey"
        "IPAM_PORT=$Port"
    ) -join "`n"

    # UTF-8 without BOM so Docker Compose reads the first line cleanly
    [System.IO.File]::WriteAllText($envPath, $content + "`n", (New-Object System.Text.UTF8Encoding($false)))

    Write-Host "[OK] Wrote $envPath" -ForegroundColor Green
    Write-Host "     API: http://127.0.0.1:$Port/docs" -ForegroundColor Cyan
    Write-Host "     Development API key (shown once; it's also in .env):" -ForegroundColor Cyan
    Write-Host "     $apiKey"
}
catch {
    Write-Error "Failed to create .env: $($_.Exception.Message)"
    exit 1
}
