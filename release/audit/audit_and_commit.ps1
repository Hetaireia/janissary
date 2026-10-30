$ErrorActionPreference = "Stop"
Set-Location "C:\Users\M5 E60\janissary-project\janissary"

# Clear stale logs
Get-ChildItem "scripts\audit-v*.txt" -ErrorAction SilentlyContinue | Remove-Item -Force

Write-Host "`n=== Running audit ===" -ForegroundColor Cyan
$auditExit = 0
try {
    & "C:\Users\M5 E60\janissary-project\janissary\scripts\fresh_clone_audit.ps1"
    $auditExit = $LASTEXITCODE
} catch {
    Write-Host "`n[audit threw] $_" -ForegroundColor Red
    $auditExit = 1
} finally {
    # ALWAYS escape the clone, even if the audit crashed mid-run
    Set-Location "C:\Users\M5 E60\janissary-project\janissary"
    # Cleanup any leftover clone
    Get-ChildItem "C:\Users\M5 E60" -Directory -Filter "janissary-audit-*" -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-30) } |
        ForEach-Object { Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue }
}

# Find the log
$log = Get-ChildItem "scripts\audit-v*.txt" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $log) { throw "audit produced no log file" }
Write-Host "`n  log: $($log.Name) ($($log.Length) bytes)" -ForegroundColor Cyan

$logText = Get-Content $log.FullName -Raw

# Gate: refuse to commit unless audit truly verified
if ($auditExit -ne 0) {
    Write-Host "`n[FAIL] audit exit code $auditExit" -ForegroundColor Red
    Write-Host "  last 30 log lines:" -ForegroundColor Yellow
    Get-Content $log.FullName -Tail 30 | ForEach-Object { "  $_" }
    throw "audit failed (exit $auditExit)"
}
if ($logText -notmatch "SHIPPED ARTIFACT VERIFIED") {
    Write-Host "`n[FAIL] no verification banner in log" -ForegroundColor Red
    Get-Content $log.FullName -Tail 30 | ForEach-Object { "  $_" }
    throw "audit did not reach verification banner"
}
if ($logText -notmatch "installed version matches pyproject") {
    throw "log missing step 9 version assertion"
}
Write-Host "`n[ok] audit verified - committing" -ForegroundColor Green

# Copy artifacts
Copy-Item $log.FullName "release\audit\audit-v7.7.1-fresh-clone.txt" -Force
Copy-Item "scripts\fresh_clone_audit.ps1" "release\audit\fresh_clone_audit.ps1" -Force

# Commit
$msg = @"
audit: v7.7.1 fresh-clone verification (closes banner drift in 986bebf)

4b2d75f committed an audit log whose content contradicted its message. The log shows the audit failed at step 9 (pip install failed, --quiet suppressed diagnostics). The message claimed "Fresh-venv install: __version__ = pip show = pyproject = 7.7.1" and "Full unit suite: 566 passed" - neither was in the log. Message also claimed the clone was at 241fde1 when actual HEAD was b796cd8.

Root cause is structural. Every false-claim commit in this chain (296db18, 24f8c28, f8d5584, 0346f6a, b796cd8, 4b2d75f) fired when multi-line paste to the PowerShell prompt continued after throw() - each line runs independently. The remedy is a wrapper .ps1 with \$ErrorActionPreference = "Stop", which does halt on throw. This commit ships that wrapper.

Fixes in this commit:
- Step 4 tag check now reads version from pyproject.toml (was hardcoded v7.7.0; same version-in-source drift class as __init__.py pre-7.7.1).
- Step 9 pip install now captures and logs full output on failure (was --quiet | Out-Null, so failures had no context).
- New release/audit/audit_and_commit.ps1 wrapper: runs audit, checks for verification banner, commits ONLY on success. If audit fails, wrapper throws and no commit happens.

The log committed here comes from an audit run whose RESULT banner matches the version asserted in step 3 and step 9. ad0e84b's committed log had a v7.7.0 banner despite 7.7.1 being the actual asserted version (step 3 verified pyproject = 7.7.1, step 9 verified installed __version__ = 7.7.1). This commit's log banner shows v7.7.1.

False-claim commit chain corrected by this commit (7 total):
  296db18 - README + CHANGELOG claimed, only CHANGELOG updated
  24f8c28 - corpus update claimed, not delivered
  f8d5584 - corpus update claimed, not delivered
  0346f6a - cases.csv + runs claimed, not staged
  b796cd8 - audit "verification" claimed, failed at step 10
  4b2d75f - audit "verification" claimed, failed at step 9

Every one fixed forward with a commit naming the misstep. This is the first in the chain whose message matches its artifact.
"@
$msg | Set-Content "scripts\audit-commit-msg.txt" -Encoding UTF8

git add release\audit\audit-v7.7.1-fresh-clone.txt release\audit\fresh_clone_audit.ps1 release\audit\audit_and_commit.ps1
git diff --cached --stat
git commit -F "scripts\audit-commit-msg.txt"
if ($LASTEXITCODE -ne 0) { throw "commit failed" }

git push origin wip/phase-4-fn3:main
if ($LASTEXITCODE -ne 0) { throw "main push failed" }
git push origin wip/phase-4-fn3
if ($LASTEXITCODE -ne 0) { throw "branch push failed" }

Write-Host "`n=== Final state ===" -ForegroundColor Cyan
git log --oneline -4
git status -sb
"GitHub main: " + ((git ls-remote origin refs/heads/main) -split '\s+')[0]
"Local HEAD:  " + (git rev-parse HEAD)
