# Export track_c container volumes to ./volumes-backup/
# Usage: .\scripts\export-volumes.ps1
# Produces: volumes-backup/<container>/<sanitized-dest>/  (per container)
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

$backupRoot = "volumes-backup"
if (-not (Test-Path $backupRoot)) { New-Item -ItemType Directory -Path $backupRoot | Out-Null }

$containers = @(docker ps -a --format "{{.Names}}" | Where-Object { $_ -match "^janissary-trackc-|^crapi-|^postgresdb$|^mongodb$|^mailhog$|^chromadb$|^api.mypremiumdealership.com$" })
if ($containers.Count -eq 0) { throw "no track_c containers found" }

foreach ($c in $containers) {
    $mounts = @(docker inspect $c --format "{{range .Mounts}}{{.Destination}}|{{.Type}}{{println}}{{end}}" 2>$null | Where-Object { $_ -and $_ -match "\|(volume|bind)$" })
    if ($mounts.Count -eq 0) { Write-Host "  $c : no volumes"; continue }
    $cDir = Join-Path $backupRoot $c
    if (-not (Test-Path $cDir)) { New-Item -ItemType Directory -Path $cDir | Out-Null }
    foreach ($m in $mounts) {
        $dest = ($m -split "\|")[0]
        $sanitized = $dest.TrimStart("/").Replace("/","_")
        if (-not $sanitized) { $sanitized = "root" }
        $target = Join-Path $cDir $sanitized
        if (Test-Path $target) { Remove-Item $target -Recurse -Force }
        Write-Host "  $c : $dest -> $target"
        docker cp "${c}:$dest" $target | Out-Null
        if ($LASTEXITCODE -ne 0) { Write-Host "  [warn] docker cp failed for $c : $dest" -ForegroundColor Yellow }
    }
}
Write-Host "`n[ok] volumes exported to $backupRoot/" -ForegroundColor Green
