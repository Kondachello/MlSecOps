@echo off
chcp 65001 >nul
setlocal enableextensions

rem ============================================================================
rem  stop.cmd - stop the local dev stack (ports 8000/5000/8501).
rem  (ASCII-only on purpose: cmd.exe mis-parses non-ASCII .cmd files.)
rem  Run:   infra\stop.cmd
rem ============================================================================

set "FOUND="
for %%p in (8000 5000 8501) do (
  for /f "tokens=5" %%P in ('netstat -ano ^| findstr ":%%p " ^| findstr LISTENING') do (
    echo Killing PID %%P on port %%p
    taskkill /F /PID %%P >nul 2>nul
    set "FOUND=1"
  )
)
if not defined FOUND echo No listeners found on ports 8000/5000/8501.
echo Done.
endlocal
