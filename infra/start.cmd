@echo off
chcp 65001 >nul
setlocal enableextensions

rem ============================================================================
rem  start.cmd - launch the whole local dev stack with one command.
rem  (ASCII-only on purpose: cmd.exe mis-parses non-ASCII .cmd files.)
rem
rem  Run from repo root (PowerShell or cmd):   infra\start.cmd
rem  Or just double-click the file.
rem
rem  Opens three windows:
rem    1) MLflow server  :5000  (sqlite store + file artifacts OUTSIDE the repo)
rem    2) Backend (API)  :8200  (with the /mlflow auth-proxy)
rem    3) Streamlit UI   :8501
rem
rem  MLflow data goes to %USERPROFILE%\mlsec_mlflow (clean path, no spaces/cyrillic)
rem  - otherwise MLflow breaks parsing the file:// artifact URI.
rem
rem  WHY 8200 AND NOT 8000: on Windows with Hyper-V / WSL2 / Docker Desktop, winnat
rem  reserves dynamic TCP ranges (e.g. 7904-8003) and 8000 often lands inside one.
rem  A native (non-Hyper-V) process like uvicorn then FAILS to bind with WinError
rem  10013 ("access denied") even though nothing is listening. 8200 sits in the
rem  free band (8104-14088). Inspect reservations with:
rem      netsh int ipv4 show excludedportrange protocol=tcp
rem  Docker compose still uses 8000 (container-internal; not affected by this).
rem ============================================================================

rem Repo root = parent of this script's folder; make it current (children inherit).
set "REPO=%~dp0.."
cd /d "%REPO%"

rem Backend API port (kept OUT of the Hyper-V/winnat reserved ranges; see note above).
set "API_PORT=8200"

rem MLflow store and artifacts (forward slashes for the file:// URI).
set "MLDATA=%USERPROFILE%\mlsec_mlflow"
set "ARTDIR=%MLDATA%\artifacts"
if not exist "%ARTDIR%" mkdir "%ARTDIR%"
set "MLDATA_FS=%MLDATA:\=/%"
set "STORE=sqlite:///%MLDATA_FS%/mlflow.db"
set "ARTURI=file:///%MLDATA_FS%/artifacts"

rem Shared environment (child windows inherit it from this parent).
set "DB_BACKEND=sqlite"
if not defined BOOTSTRAP_ADMIN_PASSWORD set "BOOTSTRAP_ADMIN_PASSWORD=admin-pass"
set "MLFLOW_UPSTREAM_URL=http://127.0.0.1:5000"
set "GATEKEEPER_URL=http://localhost:%API_PORT%"
set "APP_DEBUG=true"

echo Repo:         %REPO%
echo MLflow store: %STORE%
echo Artifacts:    %ARTURI%
echo Backend port: %API_PORT%
echo.

rem 0) Seed the first admin (idempotent).
python -m infra.seed_admin

rem 1) MLflow (single worker - more stable on Windows, no orphan workers).
start "MLflow :5000" cmd /k python -X utf8 -m mlflow server --backend-store-uri "%STORE%" --artifacts-destination "%ARTURI%" --host 127.0.0.1 --port 5000 --workers 1

rem Give MLflow a moment to bind before starting the rest.
timeout /t 3 /nobreak >nul

rem 2) Backend (FastAPI + auth-proxy to MLflow).
start "Backend :%API_PORT%" cmd /k python -X utf8 -m uvicorn src.api.main:app --host 127.0.0.1 --port %API_PORT%

rem 3) Streamlit UI.
start "UI :8501" cmd /k python -X utf8 -m streamlit run ui/app.py --server.port 8501

echo.
echo Started. Open:
echo   UI:      http://localhost:8501   (login msecops / %BOOTSTRAP_ADMIN_PASSWORD%)
echo   API:     http://localhost:%API_PORT%/docs
echo   MLflow:  http://localhost:5000
echo.
echo Each service runs in its own window. To stop: close the windows or run infra\stop.cmd
endlocal
