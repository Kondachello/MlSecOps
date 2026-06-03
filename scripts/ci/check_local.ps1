# Этап 0 — локальные проверки (Windows PowerShell). Аналог check_local.sh
$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
Set-Location $Root

Write-Host "=== demo data ==="
$prevEa = $ErrorActionPreference
$ErrorActionPreference = "Continue"
python -m pip install -q pandas numpy pyarrow 2>&1 | Out-Null
$ErrorActionPreference = $prevEa
python data/make_datasets.py
if ($LASTEXITCODE -ne 0) { throw "make_datasets failed" }

Write-Host "=== G1 clean (expect exit 0) ==="
python src/gates/data_gate/data_gate.py --path data/train_m1_clean.csv --json
if ($LASTEXITCODE -ne 0) { throw "G1 clean failed" }

Write-Host "=== G1 poisoned (expect exit 1) ==="
python src/gates/data_gate/data_gate.py --path data/train_m1_poisoned.csv --json 2>$null
if ($LASTEXITCODE -eq 0) { throw "G1 poisoned must fail" }

Write-Host "=== G3 clean (expect exit 0) ==="
python src/gates/dependency_gate/dependency_gate.py --path demo/requirements_clean.txt --json
if ($LASTEXITCODE -ne 0) { throw "G3 clean failed" }

Write-Host "=== G3 bad (expect exit 1) ==="
python src/gates/dependency_gate/dependency_gate.py --path demo/insecure/requirements_vuln.txt --json 2>$null
if ($LASTEXITCODE -eq 0) { throw "G3 bad must fail" }

Write-Host "=== G5 complete card (expect exit 0) ==="
python src/gates/registry_gate/registry_gate.py --card demo/model_card_complete.json --json
if ($LASTEXITCODE -ne 0) { throw "G5 complete failed" }

Write-Host "=== G5 incomplete card (expect exit 1) ==="
$ErrorActionPreference = "Continue"
python src/gates/registry_gate/registry_gate.py --card demo/insecure/model_card_incomplete.json --json 2>&1 | Out-Null
$ErrorActionPreference = $prevEa
if ($LASTEXITCODE -eq 0) { throw "G5 incomplete must fail" }

Write-Host "=== G4 fixtures ==="
python demo/insecure/make_model_fixtures.py
python src/gates/model_gate/model_gate.py --path demo/model_safe.safetensors --json
if ($LASTEXITCODE -ne 0) { throw "G4 safe failed" }
python src/gates/model_gate/model_gate.py --path demo/insecure/model_unsafe.pkl --json 2>$null
if ($LASTEXITCODE -eq 0) { throw "G4 pkl must fail" }

Write-Host "=== stage 0-1: basic + G4/G5 checks OK ==="
