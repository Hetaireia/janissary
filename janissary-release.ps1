<#
.SYNOPSIS
  JANISSARY 7.3.0 release automation — stepwise, gated by release-state.json.
  Option A: no scored benchmark claim. Guard refuses F1/Precision without run artifacts.
.EXAMPLE
  .\janissary-release.ps1 -Step 1
  .\janissary-release.ps1 -Step 4 -Force
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidateSet(1,2,3,4,5,6,7)][int]$Step,
  [string]$Version = '7.3.0',
  [switch]$DryRun,
  [switch]$Force
)

$ErrorActionPreference = 'Stop'
$RepoRoot  = $PSScriptRoot
$StatePath = Join-Path $RepoRoot 'release-state.json'
$OutDir    = Join-Path $RepoRoot 'release/out'
$TplDir    = Join-Path $RepoRoot 'release/templates'
$ImageRepo = 'oraclemode337/janissary'
$Pkg       = 'janissary'

function Load-State { if (Test-Path $StatePath) { Get-Content $StatePath -Raw | ConvertFrom-Json } else { [pscustomobject]@{ Version=$Version; ImageDigest=$null; Completed=@() } } }
function Save-State($s) { $s | ConvertTo-Json -Depth 5 | Set-Content $StatePath -Encoding UTF8 }
function Have($n) { (Load-State).Completed -contains "$n" }
function Mark($n) { $s = Load-State; if ($s.Completed -notcontains "$n") { $s.Completed = @($s.Completed) + "$n" }; Save-State $s }
function Require([int[]]$deps) { foreach ($d in $deps) { if (-not (Have $d)) { throw "Step $d must complete first. Run: .\janissary-release.ps1 -Step $d" } } }
function Ok($m)   { Write-Host "OK:   $m" -ForegroundColor Green }
function Note($m) { Write-Host "INFO: $m" -ForegroundColor Cyan }
function Fail($m) { Write-Host "FAIL: $m" -ForegroundColor Red; throw $m }
function Need($c) { if (-not (Get-Command $c -ErrorAction SilentlyContinue)) { Fail "missing tool: $c" } }

switch ($Step) {

1 {
  Note "Step 1 - preflight"
  foreach ($t in 'git','gh','python') { Need $t; Ok "tool: $t" }

  $b = (& git rev-parse --abbrev-ref HEAD).Trim()
  if ($b -ne 'main') { Fail "branch is '$b', not 'main'" }
  $dirty = & git status --porcelain
  if ($dirty) { Fail "working tree dirty: $($dirty -join '; ')" }
  Ok "clean tree on main"

  try { $r = Invoke-RestMethod "https://pypi.org/pypi/$Pkg/$Version/json" -TimeoutSec 20 }
  catch { Fail "PyPI $Pkg==$Version not found ($($_.Exception.Message))" }
  if (-not $r.info.version) { Fail "PyPI metadata missing" }
  Ok "PyPI $Pkg==$Version"

  $tag = Invoke-RestMethod "https://hub.docker.com/v2/repositories/$ImageRepo/tags/$Version/" -TimeoutSec 20
  $lat = Invoke-RestMethod "https://hub.docker.com/v2/repositories/$ImageRepo/tags/latest/" -TimeoutSec 20
  if (-not $tag.digest) { Fail "docker :$Version missing digest" }
  if ($tag.digest -ne $lat.digest) { Fail ":latest ($($lat.digest)) != :$Version ($($tag.digest))" }
  Ok "docker digest $($tag.digest) == :latest"

  & git rev-parse -q --verify "refs/tags/$Version" *> $null
  if ($LASTEXITCODE -eq 0) { Fail "local tag $Version already exists" }
  & gh release view $Version *> $null
  if ($LASTEXITCODE -eq 0) { Fail "GitHub release $Version already exists" }
  Ok "tag/release $Version unused"

  & gh auth status *> $null
  if ($LASTEXITCODE -ne 0) { Fail "gh not authenticated" }
  Ok "gh authenticated"

  $s = Load-State; $s.Version = $Version; $s.ImageDigest = $tag.digest; Save-State $s
  Mark 1
  Ok "Step 1 complete"
}

2 {
  Note "Step 2 - render release notes"
  Require @(1)
  if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
  $tpl = Join-Path $TplDir 'notes.md.tmpl'
  if (-not (Test-Path $tpl)) { Fail "template missing: $tpl" }

  $s = Load-State
  $text = Get-Content $tpl -Raw
  $vars = @{ VERSION=$s.Version; IMAGE_REPO=$ImageRepo; IMAGE_DIGEST=$s.ImageDigest; PKG=$Pkg }
  foreach ($k in $vars.Keys) { $text = $text -replace "\{\{$k\}\}", $vars[$k] }
  if ($text -match '\{\{[A-Z0-9_]+\}\}') { Fail "unresolved template vars" }

  $claims = ($text -match '(?i)\bF1\b') -or ($text -match '(?i)Precision')
  if ($claims) {
    $runs = Join-Path $RepoRoot 'benchmark/track_a/runs'
    $manifests = if (Test-Path $runs) { @(Get-ChildItem $runs -Recurse -Filter manifest.json -ErrorAction SilentlyContinue) } else { @() }
    if ($manifests.Count -eq 0) { Fail "notes claim F1/Precision but no manifest.json under benchmark/track_a/runs/ - refusing to publish unbacked benchmark claim" }
    Ok "benchmark claim backed by $($manifests.Count) manifest(s)"
  } else {
    Ok "no benchmark claim in notes (Option A framing)"
  }

  $out = Join-Path $OutDir 'notes.md'
  Set-Content -Path $out -Value $text -Encoding UTF8
  Ok "rendered $out"
  Mark 2
  Ok "Step 2 complete - inspect release/out/notes.md before Step 3"
}

3 {
  Note "Step 3 - commit + tag + push"
  Require @(1,2)
  if (-not $Force) { Fail "refusing without -Force (this pushes a tag)" }
  if ($DryRun) { Note "DRY RUN - would commit/tag/push $Version"; break }

  & git add -A
  & git diff --cached --quiet
  if ($LASTEXITCODE -ne 0) {
    & git commit -m "chore(release): $Version code-freeze release"
    if ($LASTEXITCODE -ne 0) { Fail "commit failed" }
    Ok "committed"
  } else { Note "nothing to commit" }

  & git push
  if ($LASTEXITCODE -ne 0) { Fail "push failed" }
  & git tag -a $Version -m "JANISSARY $Version"
  if ($LASTEXITCODE -ne 0) { Fail "tag failed" }
  & git push origin $Version
  if ($LASTEXITCODE -ne 0) { Fail "tag push failed" }
  Ok "tag $Version pushed"
  Mark 3
  Ok "Step 3 complete"
}

4 {
  Note "Step 4 - create GitHub Release"
  Require @(3)
  if (-not $Force) { Fail "refusing without -Force (publishes the release)" }
  if ($DryRun) { Note "DRY RUN - would create GitHub release $Version"; break }
  $notes = Join-Path $OutDir 'notes.md'
  if (-not (Test-Path $notes)) { Fail "notes not rendered - run Step 2" }
  & gh release create $Version --title "v$Version - Code Freeze Release" --notes-file $notes
  if ($LASTEXITCODE -ne 0) { Fail "gh release create failed" }
  Ok "release $Version published"
  Mark 4
  Ok "Step 4 complete"
}

5 {
  Note "Step 5 - post-release verification"
  Require @(4)
  $s = Load-State

  & gh release view $s.Version *> $null
  if ($LASTEXITCODE -ne 0) { Fail "release not visible via gh" }
  Ok "release visible"

  $notes = (& gh release view $s.Version --json body -q .body) -join "`n"
  foreach ($needle in 'Pathtraver','No scored performance claim') {
    if ($notes -notmatch [regex]::Escape($needle)) { Fail "notes missing '$needle'" }
  }
  Ok "notes carry required disclosures"

  $tag = Invoke-RestMethod "https://hub.docker.com/v2/repositories/$ImageRepo/tags/$($s.Version)/" -TimeoutSec 20
  $lat = Invoke-RestMethod "https://hub.docker.com/v2/repositories/$ImageRepo/tags/latest/" -TimeoutSec 20
  if ($tag.digest -ne $lat.digest) { Fail ":latest drifted ($($lat.digest))" }
  Ok ":latest == :$($s.Version) ($($tag.digest))"

  $venv = Join-Path $env:TEMP ("janissary-smoke-" + (Get-Random))
  & python -m venv $venv | Out-Null
  & "$venv\Scripts\pip.exe" -q install "$Pkg==$($s.Version)"
  if ($LASTEXITCODE -ne 0) { Fail "pip install smoke failed" }
  $ver = (& "$venv\Scripts\janissary.exe" --version) -join ''
  if ($ver -notmatch [regex]::Escape($s.Version)) { Fail "janissary --version = '$ver'" }
  Remove-Item -Recurse -Force $venv -ErrorAction SilentlyContinue
  Ok "pip install + --version smoke OK"
  Mark 5
  Ok "Step 5 complete"
}

6 {
  Note "Step 6 - tracking issues (skipped if body files absent)"
  Require @(4)
  $specs = @(
    @{ T='feat: --mode ci (fast, unpaced pipeline mode)';        B='issue-ci.md'; L='enhancement' }
    @{ T='refactor: generalize six-oracle pattern (Issue #4)'; B='issue-4.md';  L='architecture' }
  )
  $opened = 0
  foreach ($it in $specs) {
    $bodyPath = Join-Path $OutDir $it.B
    if (-not (Test-Path $bodyPath)) { Note "skip '$($it.T)' - no body file at $bodyPath"; continue }
    $ex = & gh issue list --search "in:title `"$($it.T)`"" --json number -q '.[0].number'
    if ($ex) { Note "issue already open: #$ex"; continue }
    & gh issue create --title $it.T --body-file $bodyPath --label $it.L *> $null
    if ($LASTEXITCODE -ne 0) { Fail "issue create failed: $($it.T)" }
    Ok "opened: $($it.T)"
    $opened++
  }
  if ($opened -eq 0) { Note "no issues opened this run (body files absent or already open)" }
  Mark 6
  Ok "Step 6 complete"
}

7 {
  Note "Step 7 - DEV.to draft (published=false, hardcoded)"
  Require @(4)
  if (-not $env:DEVTO_API_KEY) { Note "DEVTO_API_KEY unset - skipping (not an error)"; break }
  $bodyPath = Join-Path $OutDir 'announcement.md'
  if (-not (Test-Path $bodyPath)) { Note "no release/out/announcement.md - skipping draft"; break }
  $body = Get-Content $bodyPath -Raw
  $title = (($body -split "`n")[0] -replace '^#\s*','').Trim()
  $payload = @{ article = @{ title=$title; body_markdown=$body; published=$false; tags=@('security','appsec','opensource') } } | ConvertTo-Json -Depth 5
  $resp = Invoke-RestMethod -Method POST -Uri 'https://dev.to/api/articles' -Headers @{ 'api-key'=$env:DEVTO_API_KEY; 'Content-Type'='application/json' } -Body $payload
  Ok "DRAFT created: $($resp.url)"
  Note "publish manually - last click stays human"
  Mark 7
  Ok "Step 7 complete"
}

}