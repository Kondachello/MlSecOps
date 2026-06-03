# run_local.ps1 — поднять весь дев-стенд локально (без Docker), Windows.
#
#   powershell -ExecutionPolicy Bypass -File infra\run_local.ps1
#
# Поднимает три процесса в отдельных окнах:
#   1) MLflow server   :5000  (sqlite-стор + file-артефакты ВНЕ репозитория)
#   2) Backend (API)   :8000  (с /mlflow auth-прокси)
#   3) Streamlit UI    :8501
#
# ВАЖНО: MLflow-данные кладём в $env:USERPROFILE\mlsec_mlflow, а НЕ в репозиторий —
# путь репо содержит пробел/кириллицу ("Новая папка"), и MLflow ломается на разборе
# file://-URI артефактов. Чистый путь это чинит.

$ErrorActionPreference = "Stop"
$Repo = Split-Path -Parent $PSScriptRoot           # корень репозитория
$MlflowData = Join-Path $env:USERPROFILE "mlsec_mlflow"
$Artifacts = Join-Path $MlflowData "artifacts"
New-Item -ItemType Directory -Force -Path $Artifacts | Out-Null

# Пути в file://-URI: прямые слэши
$StoreUri = "sqlite:///" + ($MlflowData -replace '\\','/') + "/mlflow.db"
$ArtUri   = "file:///"   + ($Artifacts  -replace '\\','/')

Write-Host "Repo:        $Repo"
Write-Host "MLflow store:$StoreUri"
Write-Host "Artifacts:   $ArtUri`n"

# 0) Сид первого админа (идемпотентно)
$env:DB_BACKEND = "sqlite"
if (-not $env:BOOTSTRAP_ADMIN_PASSWORD) { $env:BOOTSTRAP_ADMIN_PASSWORD = "admin-pass" }
Push-Location $Repo
python -m infra.seed_admin
Pop-Location

# 1) MLflow (один воркер — стабильнее на Windows, не плодит сирот)
Start-Process powershell -ArgumentList @(
  "-NoExit","-Command",
  "cd '$Repo'; python -X utf8 -m mlflow server --backend-store-uri '$StoreUri' " +
  "--artifacts-destination '$ArtUri' --host 127.0.0.1 --port 5000 --workers 1"
)

# 2) Backend (с прокси к MLflow)
Start-Process powershell -ArgumentList @(
  "-NoExit","-Command",
  "cd '$Repo'; `$env:DB_BACKEND='sqlite'; `$env:MLFLOW_UPSTREAM_URL='http://127.0.0.1:5000'; " +
  "python -X utf8 -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000"
)

# 3) UI
Start-Process powershell -ArgumentList @(
  "-NoExit","-Command",
  "cd '$Repo'; `$env:GATEKEEPER_URL='http://localhost:8000'; `$env:APP_DEBUG='true'; " +
  "python -X utf8 -m streamlit run ui/app.py --server.port 8501"
)

Write-Host "`nЗапущено. Открой:"
Write-Host "  UI:      http://localhost:8501   (логин msecops / $($env:BOOTSTRAP_ADMIN_PASSWORD))"
Write-Host "  API:     http://localhost:8000/docs"
Write-Host "  MLflow:  http://localhost:5000   (напрямую; прод — только через прокси)"
