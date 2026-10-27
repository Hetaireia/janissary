# run-baseline.ps1 - launches one 7.5.0 baseline run on track A
# Preconditions: target up on http://127.0.0.1:8080/benchmark
# Usage: .\run-baseline.ps1 -RunNumber 1 -Arm default
param(
    [Parameter(Mandatory=$true)][ValidateSet(1,2,3)][int]$RunNumber,
    [ValidateSet('default','tuned')][string]$Arm = 'default'
)
$ErrorActionPreference = 'Stop'
$repo = "C:\Users\M5 E60\janissary-project\janissary\janissary"
Set-Location $repo
$target  = 'http://127.0.0.1:8080/benchmark'
$cases   = 'benchmark/track_a/case_vectors.csv'
$envFile = "artifacts/7.5.0-baseline/invocations/tools_$Arm.env"
Write-Host "============================================"
Write-Host " 7.5.0 baseline run $RunNumber ($Arm arm)"
Write-Host " Started: $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')"
Write-Host " Target:  $target"
Write-Host " Env:     $envFile"
Write-Host "============================================"
& python -m benchmark.track_a.runner `
    --tool janissary `
    --run-number $RunNumber `
    --target-base $target `
    --cases-csv $cases `
    --tools-env $envFile
$rc = $LASTEXITCODE
Write-Host " Finished: $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ') exit=$rc"
exit $rc