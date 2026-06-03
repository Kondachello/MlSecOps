# Сборка всех образов mlsec-gate-* (Windows PowerShell).
# Запуск из любой папки:
#   powershell -File scripts/ci/build_all_gates.ps1
$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "../..")

Write-Host "Проверка Docker..."
$null = docker version 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "Docker Engine не отвечает (часто 500 на dockerDesktopLinuxEngine)."
    Write-Host "1) Quit Docker Desktop -> подождать 30 сек -> запустить снова"
    Write-Host "2) docker version  — должен быть блок Server"
    Write-Host "3) Или: docker compose -f infra/docker-compose.gates.yml build"
    exit 1
}

$gates = @(
    @{ Tag = "mlsec-gate-data";        Dir = "src\gates\data_gate" },
    @{ Tag = "mlsec-gate-code";        Dir = "src\gates\code_gate" },
    @{ Tag = "mlsec-gate-dependency";  Dir = "src\gates\dependency_gate" },
    @{ Tag = "mlsec-gate-model";       Dir = "src\gates\model_gate" },
    @{ Tag = "mlsec-gate-registry";    Dir = "src\gates\registry_gate" }
)

Set-Location $Root
foreach ($g in $gates) {
    $ctx = Join-Path $Root $g.Dir
    Write-Host "`n==> $($g.Tag)"
    docker build -t $g.Tag $ctx
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

Write-Host "`nГотово. Образы:"
docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}" | Select-String "mlsec-gate"
