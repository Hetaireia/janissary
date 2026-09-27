# Render WORKFLOW.md to HTML and open it in the default browser.
$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

$activate = Join-Path $repoRoot ".venv\Scripts\Activate.ps1"
if (Test-Path $activate) { . $activate }

python (Join-Path $PSScriptRoot "render_workflow.py")