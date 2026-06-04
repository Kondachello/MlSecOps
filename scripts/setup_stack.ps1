# Полная подготовка стенда main/ для CI/CD + UI (один запуск).
# Usage:  cd main; .\scripts\setup_stack.ps1
$ErrorActionPreference = "Stop"
$Root = Split-Path $PSScriptRoot -Parent
Set-Location $Root

if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "Created .env from .env.example — проверьте GITHUB_TOKEN"
}

$uiPort = "8501"
if (Select-String -Path ".env" -Pattern "UI_HOST_PORT=(\d+)" -Quiet) {
    $m = Select-String -Path ".env" -Pattern "UI_HOST_PORT=(\d+)" | Select-Object -First 1
    if ($m.Matches.Groups[1].Value) { $uiPort = $m.Matches.Groups[1].Value }
}
$env:UI_HOST_PORT = $uiPort

Write-Host "=== docker compose up --build ==="
docker compose -f infra/docker-compose.yml up --build -d

Write-Host "=== wait postgres ==="
$ok = $false
for ($i = 0; $i - 30; $i++) {
    $h = docker inspect mlsecops-postgres-1 --format "{{.State.Health.Status}}" 2>$null
    if ($h -eq "healthy") { $ok = $true; break }
    Start-Sleep -Seconds 2
}
if (-not $ok) { Write-Warning "postgres not healthy yet" }

Write-Host "=== ensure MLflow database ==="
docker exec mlsecops-postgres-1 psql -U mlsec_app -d postgres -tc `
    "SELECT 1 FROM pg_database WHERE datname='mlflow'" 2>$null | Out-Null
if (-not (docker exec mlsecops-postgres-1 psql -U mlsec_app -d postgres -tc `
        "SELECT 1 FROM pg_database WHERE datname='mlflow'" 2>$null).Trim()) {
    docker exec mlsecops-postgres-1 psql -U mlsec_app -d postgres -c "CREATE DATABASE mlflow;" | Out-Null
    Write-Host "  created database mlflow"
}

Write-Host "=== generate datasets ==="
python data/make_datasets.py 2>$null
if ($LASTEXITCODE -ne 0) { python "$Root\data\make_datasets.py" }

Write-Host "=== seed CI registry ==="
docker compose -f infra/docker-compose.yml exec -T backend python scripts/seed_ci_registry.py

Write-Host ""
Write-Host "=== URLs ==="
Write-Host "  UI:        http://localhost:$uiPort"
Write-Host "  API docs:  http://localhost:8000/docs"
Write-Host "  Inference: http://localhost:8080/health"
Write-Host ""
Write-Host "=== GitHub (скопируйте в repo Secrets / Variables) ==="
$token = (Select-String -Path ".env" -Pattern "^CI_INGEST_TOKEN=(.+)$" | ForEach-Object { $_.Matches.Groups[1].Value.Trim() })
Write-Host "  Secret  CI_INGEST_TOKEN = $token"
Write-Host "  Variable GATEKEEPER_URL = <публичный URL или пусто для ci без ingest>"
Write-Host "  Variable REQUIRE_COSIGN = false"
Write-Host "  См. .github/GITHUB_ACTIONS_SETUP.md"
