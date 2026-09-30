<#
.SYNOPSIS
    Creates or completes the .env file for the NEXTDC IPAM POC.

.DESCRIPTION
    Purpose      : Local set-up for the Docker Compose stack. Generates any secret that .env is missing:
                   the database password, the development API key (for scripts and tests), the key that
                   seals 2FA secrets at rest, and the first administrator's password.
    Author       : Craig McDonald (Technical Architect), drafted with Claude
    Date         : 2026-09-30
    Supported OS : Windows 10/11, Windows Server 2019+ (PowerShell 5.1 or 7+)
    Dependencies : None

    Existing values are never changed, so it's safe to re-run after an upgrade: it only adds what's
    missing. The .env file is git-ignored. Nothing is printed except which settings were added.

.PARAMETER Force
    Replace .env entirely. The database volume keeps the old password, so also run
    'docker compose down -v' (which deletes all POC data) if you do this.

.PARAMETER Port
    Host port for the API (bound to 127.0.0.1 only). Default 8820. Used only when creating IPAM_PORT.

.EXAMPLE
    .\scripts\Initialize-IpamEnv.ps1
    Then read IPAM_ADMIN_PASSWORD from .env to sign in to http://127.0.0.1:8820/ as 'admin'.
#>
[CmdletBinding()]
param(
    [switch]$Force,
    [ValidateRange(1024, 65535)]
    [int]$Port = 8820
)

$ErrorActionPreference = 'Stop'

function New-RandomBytes([int]$Count) {
    $buffer = New-Object byte[] $Count
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($buffer)
    return $buffer
}

function ConvertTo-Base64Url([byte[]]$Bytes) {
    # URL-safe, unpadded: safe in URLs, headers and .env files
    return ([Convert]::ToBase64String($Bytes)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function New-AdminPassword {
    # Meets the IPAM policy (12+ chars, three character classes). Changed at first sign-in anyway.
    $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
    $bytes = New-RandomBytes 16
    $chars = $bytes | ForEach-Object { $alphabet[$_ % $alphabet.Length] }
    return (-join $chars[0..5]) + '-' + (-join $chars[6..11]) + '-' + (-join $chars[12..15]) + '7a'
}

try {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    $envPath = Join-Path $repoRoot '.env'

    $existing = @{}
    $lines = @()
    if ((Test-Path $envPath) -and -not $Force) {
        $lines = @(Get-Content $envPath)
        foreach ($line in $lines) {
            if ($line -match '^\s*([A-Z0-9_]+)\s*=') { $existing[$Matches[1]] = $true }
        }
    }
    else {
        $lines = @('# NEXTDC IPAM POC - local development secrets. Never commit this file.')
    }

    $prefix = -join ((New-RandomBytes 4) | ForEach-Object { $_.ToString('x2') })
    $wanted = [ordered]@{
        'POSTGRES_PASSWORD'      = { ConvertTo-Base64Url (New-RandomBytes 24) }
        'IPAM_BOOTSTRAP_API_KEY' = { "ipam_${prefix}_$(ConvertTo-Base64Url (New-RandomBytes 32))" }
        'IPAM_SECRET_KEY'        = { ConvertTo-Base64Url (New-RandomBytes 32) }
        'IPAM_ADMIN_USERNAME'    = { 'admin' }
        'IPAM_ADMIN_PASSWORD'    = { New-AdminPassword }
        'IPAM_PORT'              = { "$Port" }
    }

    $added = @()
    foreach ($name in $wanted.Keys) {
        if (-not $existing.ContainsKey($name)) {
            $lines += "$name=$(& $wanted[$name])"
            $added += $name
        }
    }

    if (-not $added.Count) {
        Write-Host "[OK] $envPath already has every setting; nothing changed." -ForegroundColor Green
        return
    }

    # UTF-8 without BOM so Docker Compose reads the first line cleanly
    [System.IO.File]::WriteAllText($envPath, (($lines -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "[OK] Wrote $envPath; added: $($added -join ', ')" -ForegroundColor Green
    if ($added -contains 'IPAM_ADMIN_PASSWORD') {
        Write-Host "     Sign in at http://127.0.0.1:$Port/ as 'admin' with IPAM_ADMIN_PASSWORD from .env." -ForegroundColor Cyan
        Write-Host "     You'll be asked to change it and to set up an authenticator app." -ForegroundColor Cyan
    }
}
catch {
    Write-Error "Failed to prepare .env: $($_.Exception.Message)"
    exit 1
}
