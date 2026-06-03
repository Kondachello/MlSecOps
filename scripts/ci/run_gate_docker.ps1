# Запуск гейта в Docker (после build). Пример:
#   .\scripts\ci\run_gate_docker.ps1 -Gate data -HostPath data\train_m1_clean.csv
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("data", "code", "dependency", "model", "registry")]
    [string] $Gate,

    [Parameter(Mandatory = $true)]
    [string] $HostPath,

    [string] $Stage = "ci"
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "../..")
$full = Join-Path $Root $HostPath
if (-not (Test-Path $full)) { throw "Нет файла/папки: $full" }

$image = "mlsec-gate-$Gate"
$item = Get-Item $full
if ($item.PSIsContainer) {
    $mount = $full
    $inPath = "/in"
} else {
    $mount = $item.DirectoryName
    $inPath = "/in/$($item.Name)"
}

$args = @("run", "--rm")
if ($Gate -in @("data", "model")) { $args += "--network", "none" }
$args += "-v", "${mount}:/in:ro", $image, "--path", $inPath, "--json"
if ($Gate -eq "code") { $args += "--stage", $Stage }

Write-Host "docker $($args -join ' ')"
& docker @args
exit $LASTEXITCODE
