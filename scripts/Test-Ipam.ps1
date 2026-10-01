<#
.SYNOPSIS
    Runs the IPAM test suite against its own throwaway API and database.

.DESCRIPTION
    Purpose      : Engine unit tests plus end-to-end tests (workflows, ADR tests, sign-in/2FA, library, site retire).
                   They run against separate containers (api-test, db-test) whose database lives in memory,
                   so your real sites, pools and users are never touched. The test containers are removed afterwards.
    Author       : Craig McDonald (Technical Architect), drafted with Claude
    Date         : 2026-10-01
    Supported OS : Windows 10/11 (PowerShell 5.1 or 7+) with Docker Desktop running
    Dependencies : Docker Desktop; .env (scripts/Initialize-IpamEnv.ps1)

.PARAMETER Filter
    Optional pytest -k expression to run a subset, e.g. 'retire or pool'.

.EXAMPLE
    .\scripts\Test-Ipam.ps1
#>
[CmdletBinding()]
param(
    [string]$Filter
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot
try {
    if (-not (Test-Path (Join-Path $repoRoot '.env'))) { throw '.env is missing; run scripts\Initialize-IpamEnv.ps1 first' }
    $dockerArgs = @('compose', '--profile', 'test', 'run', '--rm', '--build', 'tests', 'python', '-m', 'pytest', '-q', '-p', 'no:cacheprovider', 'tests')
    if ($Filter) { $dockerArgs += @('-k', $Filter) }
    Write-Host '[..] Running tests in a throwaway database (your real data is not touched)' -ForegroundColor Cyan
    & docker @dockerArgs
    $code = $LASTEXITCODE
    if ($code -eq 0) { Write-Host '[OK] All tests passed' -ForegroundColor Green }
    else { Write-Host "[FAIL] Tests failed (exit $code)" -ForegroundColor Red }
}
catch {
    Write-Error "Test run failed: $($_.Exception.Message)"
    $code = 1
}
finally {
    # Remove the test API and its in-memory database; the real 'api' and 'db' keep running.
    & docker compose --profile test rm -s -f api-test db-test 2>&1 | Out-Null
    Pop-Location
}
exit $code
