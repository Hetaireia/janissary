# Import track_c container volumes from ./volumes-backup/
# Usage: .\scripts\import-volumes.ps1
# Restores state captured by export-volumes.ps1. Run AFTER containers exist but BEFORE starting the scanner.
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

$backupRoot = "volumes-backup"
if (-not (Test-Path $backupRoot)) { throw "volumes-backup/ not found — run export-volumes.ps1 first" }

$dirs = @(Get-ChildItem $backupRoot -Directory)
if ($dirs.Count -eq 0) { throw "no backups found in volumes-backup/" }

foreach ($d in $dirs) {
    $c = $d.Name
    $exists = docker ps -a --format "{{.Names}}" | Where-Object { $_ -eq $c }
    if (-not $exists) { Write-Host "  [skip] $c not present"; continue }
    foreach ($sub in @(Get-ChildItem $d.FullName -Directory)) {
        $dest = "/" + $sub.Name.Replace("_","/")
        Write-Host "  $c : $($sub.FullName) -> $dest"
        docker cp $sub.FullName "${c}:$dest" | Out-Null
        if ($LASTEXITCODE -ne 0) { Write-Host "  [warn] import failed for $c : $dest" -ForegroundColor Yellow }
    }
}
Write-Host "`n[ok] volumes imported. Restart containers if they were running." -ForegroundColor Green
