# Convenience wrapper around the pinned BenchmarkJava build + run.
# Run from the janissary repo root on Windows/PowerShell.

$repo = "C:\Users\M5 E60\janissary-project\janissary"
$ctx  = "C:\Users\M5 E60\janissary-project\owasp-benchmark"
$tag  = "janissary/owasp-benchmark:20cbf3d"

Push-Location $repo

Write-Host "--- build ---"
docker build -f benchmark/track_a/Dockerfile.owasp-benchmark -t $tag $ctx
if ($LASTEXITCODE -ne 0) { Pop-Location; exit 1 }

Write-Host "`n--- run (foreground, ctrl-c to stop) ---"
Write-Host "listening on https://localhost:8443/benchmark/"
docker run --rm -p 8443:8443 $tag

Pop-Location