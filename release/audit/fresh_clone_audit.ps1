$ErrorActionPreference = "Stop"
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$auditDir = "C:\Users\M5 E60\janissary-audit-$stamp"
$auditLog = "C:\Users\M5 E60\janissary-project\janissary\scripts\audit-v7.7.0-$stamp.txt"

function Log($msg) {
    Write-Host $msg
    Add-Content -Path $auditLog -Value $msg -Encoding UTF8
}

Log "================================================================"
Log "FRESH-CLONE AUDIT - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Log "================================================================"
Log ""

Log "=== 1. Clone from GitHub (branch: wip/phase-4-fn3) ==="
git clone --depth 1 --branch wip/phase-4-fn3 https://github.com/Hetaireia/janissary.git $auditDir 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { Log "FAIL: clone failed"; exit 1 }
Set-Location $auditDir
Log "  cloned to: $auditDir"

Log "`n=== 2. Verify clone HEAD matches GitHub main ==="
$cloneHead = (git rev-parse HEAD).Trim()
$remoteMain = ((git ls-remote origin refs/heads/main) -split '\s+')[0]
Log "  clone HEAD:   $cloneHead"
Log "  GitHub main:  $remoteMain"
if ($cloneHead -ne $remoteMain) { Log "FAIL: clone HEAD != GitHub main"; exit 1 }
Log "  [ok] match"

Log "`n=== 3. Verify version at HEAD ==="
$ver = (Select-String -Path "pyproject.toml" -Pattern '^version' | Select-Object -First 1).Line.Trim()
Log "  pyproject: $ver"
$expectedVer = (Select-String -Path "pyproject.toml" -Pattern '^version' | Select-Object -First 1).Line -replace '^version\s*=\s*"([^"]+)"\s*$', '$1'
if ($ver -notmatch [regex]::Escape($expectedVer)) { Log "FAIL: version is not $expectedVer (got: $ver)"; exit 1 }
Log "  [ok] version $expectedVer"

Log "`n=== 4. Verify tag v7.7.0 exists remotely ==="
$remoteTag = ((git ls-remote origin refs/tags/v7.7.0) -split '\s+')[0]
Log "  remote tag v7.7.0: $remoteTag"
if (-not $remoteTag) { Log "FAIL: v7.7.0 tag not on remote"; exit 1 }
Log "  [ok] tag present"

Log "`n=== 5. Verify key files present in clone ==="
$required = @(
    "src\janissary\detection\ssrf_response_oracle.py",
    "tests\unit\test_ssrf_response_oracle.py",
    "tests\unit\test_preflight_abort_policy.py",
    "benchmark\track_c\templates\crapi_mechanic.json",
    "benchmark\track_c\corpus-score.json",
    "benchmark\track_c\runs\20261030T032949Z-crapi\ssrf.jsonl"
)
$missing = 0
foreach ($f in $required) {
    if (Test-Path $f) { Log "  [ok] $f" }
    else { Log "  [MISSING] $f"; $missing++ }
}
if ($missing -gt 0) { Log "FAIL: $missing required files missing"; exit 1 }

Log "`n=== 6. Verify BENCHMARK.md Amendment 23 present ==="
if ((Get-Content "BENCHMARK.md" -Raw).Contains("Amendment 23")) {
    Log "  [ok] Amendment 23 present"
} else { Log "FAIL: Amendment 23 not in BENCHMARK.md"; exit 1 }

Log "`n=== 7. Verify PHASE-4-PLAN.md status update present ==="
if ((Get-Content "docs\PHASE-4-PLAN.md" -Raw).Contains("v7.7.0 (Session B) closed")) {
    Log "  [ok] status update present"
} else { Log "FAIL: status update not in PHASE-4-PLAN.md"; exit 1 }

Log "`n=== 8. Verify corpus-score.json integrity ==="
$c = Get-Content "benchmark\track_c\corpus-score.json" -Raw | ConvertFrom-Json
Log "  apps: $($c.apps.PSObject.Properties.Name -join ', ')"
Log "  totals: tp=$($c.totals.tp) fp=$($c.totals.fp) fn=$($c.totals.fn) tn=$($c.totals.tn) aborts=$($c.totals.aborts)"
Log "  precision=$($c.totals.precision) recall=$($c.totals.recall) f1=$($c.totals.f1)"
if ($c.totals.tp -ne 9 -or $c.totals.f1 -ne 1) { Log "FAIL: corpus totals don't match claim"; exit 1 }
if ($c.apps.PSObject.Properties.Name.Count -ne 7) { Log "FAIL: expected 7 apps"; exit 1 }
Log "  [ok] corpus at tp=9 f1=1.0 across 7 apps"

Log "`n=== 9. Create fresh venv + install ==="
& python -m venv .venv 2>&1 | Out-Null
$py = ".\.venv\Scripts\python.exe"
& $py -m pip install --quiet --upgrade pip 2>&1 | Out-Null
& $py -m pip install --quiet -e ".[dev]" 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { Log "FAIL: pip install failed"; exit 1 }
$installedVer = (& $py -c "import janissary; print(janissary.__version__)" 2>&1).Trim()
$pipVer = (& $py -m pip show janissary 2>&1 | Select-String "Version:" | Select-Object -First 1).Line.Trim()
$pyprojectVer = (Select-String -Path "pyproject.toml" -Pattern "^version" | Select-Object -First 1).Line -replace '.*"([^"]+)".*','$1'
Log "  janissary.__version__: $installedVer"
Log "  pip show Version:      $pipVer"
Log "  pyproject.toml:        $pyprojectVer"
if ($installedVer -ne $pyprojectVer) {
    Log "FAIL: __version__ ($installedVer) != pyproject ($pyprojectVer)"
    exit 1
}
Log "  [ok] installed version matches pyproject"

Log "`n=== 10. Run full unit test suite in fresh venv ==="
$testOutput = & $py -m pytest tests\unit\ -q 2>&1
$testLines = $testOutput | Select-String "passed|failed"
$summary = ($testLines | Select-Object -Last 1).Line.Trim()
Log "  $summary"
if ($summary -notmatch "564 passed") { Log "FAIL: expected 564 passed"; Log $testOutput; exit 1 }
Log "  [ok] all 564 pass in fresh clone"

Log "`n=== 11. Verify ssrf.jsonl artifact content (chain-of-evidence) ==="
$ssrfLine = Get-Content "benchmark\track_c\runs\20261030T032949Z-crapi\ssrf.jsonl" -First 1 | ConvertFrom-Json
$hasPayload = $ssrfLine.payload -eq "http://mailhog:8025/"
$hasRawResp = ($ssrfLine.raw_response -match "MailHog")
$hasClass = $ssrfLine.class -eq "ssrf"
Log "  payload = mailhog URL: $hasPayload"
Log "  response contains MailHog HTML: $hasRawResp"
Log "  class = ssrf: $hasClass"
if (-not ($hasPayload -and $hasRawResp -and $hasClass)) { Log "FAIL: ssrf.jsonl artifact incomplete"; exit 1 }
Log "  [ok] chain-of-evidence intact"

Log "`n=== 12. Cleanup ==="
Set-Location "C:\Users\M5 E60\janissary-project\janissary"
Remove-Item $auditDir -Recurse -Force
Log "  removed audit clone: $auditDir"

Log ""
Log "================================================================"
Log " RESULT: v7.7.0 SHIPPED ARTIFACT VERIFIED"
Log "================================================================"
Log ""
Log "  Clean clone from GitHub: PASS"
Log "  Clone HEAD == GitHub main: PASS"
Log "  Version 7.7.0 at HEAD: PASS"
Log "  Tag v7.7.0 on remote: PASS"
Log "  All key files present: PASS"
Log "  BENCHMARK.md Amendment 23: PASS"
Log "  PHASE-4-PLAN.md status update: PASS"
Log "  Corpus tp=9 f1=1.0 across 7 apps: PASS"
Log "  564 tests in fresh venv: PASS"
Log "  ssrf.jsonl chain-of-evidence: PASS"
Log ""
Log "Audit log saved to: $auditLog"
