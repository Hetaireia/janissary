<#
.SYNOPSIS
    Deterministic demo scan for recording demo.gif (M7).

.DESCRIPTION
    Runs a fixed sequence of JANISSARY scans against OWASP Juice Shop and
    prints the output. Designed for screen recording with ScreenToGif or
    similar; see docs/DEMO.md for the recording workflow.

    Two scans:
      1. A known-vulnerable endpoint on Juice Shop's RETAIL SQLi surface
         (/rest/products/search?q=) -> expect a CRITICAL sqli finding.
      2. A safe endpoint (/rest/admin/application-version) -> expect a
         "Negative result: no findings" line (M18).

    Both scans run with the normal human-readable output (not --quiet),
    so the demo shows the full banner, per-request progress, and summary.

.PARAMETER NoStart
    Do not start Juice Shop if it is not running. Fail instead.

.EXAMPLE
    .\tools\demo-scan.ps1
#>

param(
    [switch]$NoStart
)

$ErrorActionPreference = "Stop"

function Write-DemoHeader([string]$msg) {
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host $msg -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Start-Sleep -Milliseconds 400
}

function Test-JuiceShop {
    try {
        $null = Invoke-WebRequest -Uri "http://127.0.0.1:3000/rest/admin/application-version" -TimeoutSec 3 -UseBasicParsing -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $repo
try {
    if (-not (Test-Path ".\.venv\Scripts\janissary.exe")) {
        throw "janissary not found in .venv; run 'pip install -e .' in the venv first"
    }

    Write-DemoHeader "JANISSARY demo scan"
    Write-Host "Repo:   $repo"
    Write-Host "Target: OWASP Juice Shop on http://127.0.0.1:3000"

    if (-not (Test-JuiceShop)) {
        if ($NoStart) {
            throw "Juice Shop not running and -NoStart given"
        }
        Write-Host ""
        Write-Host "[*] Juice Shop not running; starting container..." -ForegroundColor Yellow
        & docker run -d --rm --name janissary-demo-juice -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v17.1.1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "docker run failed; is Docker Desktop running?"
        }
        Write-Host "[*] waiting for Juice Shop on :3000 (up to 120s)..." -ForegroundColor Yellow
        $ready = $false
        for ($i = 0; $i -lt 60; $i++) {
            if (Test-JuiceShop) { $ready = $true; break }
            Start-Sleep -Seconds 2
        }
        if (-not $ready) {
            & docker stop janissary-demo-juice 2>&1 | Out-Null
            throw "Juice Shop did not become ready in 120s"
        }
        Write-Host "[*] Juice Shop ready" -ForegroundColor Green
    } else {
        Write-Host "[*] Juice Shop already running" -ForegroundColor Green
    }

    $env:JANISSARY_ACCEPT_TERMS = "1"

    Write-DemoHeader "SCAN 1 - SQL injection on Juice Shop RETAIL search"
    Write-Host "Command: janissary scan -u 'http://127.0.0.1:3000/rest/products/search?q=test' -p q" -ForegroundColor DarkGray
    Write-Host ""
    Start-Sleep -Milliseconds 800
    & .\.venv\Scripts\janissary.exe scan -u "http://127.0.0.1:3000/rest/products/search?q=test" -p q
    $exit1 = $LASTEXITCODE
    Write-Host ""
    Write-Host "[*] scan 1 exit code: $exit1 (1 = findings present)" -ForegroundColor Yellow
    Start-Sleep -Seconds 2

    Write-DemoHeader "SCAN 2 - clean scan on a safe endpoint (negative result, M18)"
    Write-Host "Command: janissary scan -u 'http://127.0.0.1:3000/rest/admin/application-version' -p q" -ForegroundColor DarkGray
    Write-Host ""
    Start-Sleep -Milliseconds 800
    & .\.venv\Scripts\janissary.exe scan -u "http://127.0.0.1:3000/rest/admin/application-version" -p q
    $exit2 = $LASTEXITCODE
    Write-Host ""
    Write-Host "[*] scan 2 exit code: $exit2 (0 = clean, no findings)" -ForegroundColor Yellow
    Start-Sleep -Seconds 1

    Write-DemoHeader "DONE"
    Write-Host "Positive + negative results both demonstrated." -ForegroundColor Green
    Write-Host "Recording reference: docs/DEMO.md" -ForegroundColor Green
} finally {
    Remove-Item Env:\JANISSARY_ACCEPT_TERMS -ErrorAction SilentlyContinue
    Pop-Location
}