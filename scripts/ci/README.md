# scripts/ci — обёртки для CI/CD

| Скрипт | Назначение |
|--------|------------|
| `run_gate.sh` | Гейт через Python (Git Bash) |
| `build_all_gates.sh` | Сборка образов (Git Bash) |
| `build_all_gates.ps1` | **Сборка образов (PowerShell)** |
| `run_gate_docker.ps1` | Запуск гейта в контейнере после build |
| `parse_report.py` | Краткий вывод JSON-отчёта |
| `check_local.sh` | Проверка этапа 0 без Docker |

## Docker: сборка всех гейтов (Windows)

**Сначала:** `docker version` — должен быть блок **Server**. Если 500 — перезапусти Docker Desktop.

Одна команда на образ (не две в одной строке):

```powershell
cd alfa_case_2
docker compose -f infra/docker-compose.gates.yml build
```

Или:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/ci/build_all_gates.ps1
```

Проверка G1 в контейнере:

```powershell
.\scripts\ci\run_gate_docker.ps1 -Gate data -HostPath data\train_m1_clean.csv
```

Без Docker — только Python: `python src/gates/data_gate/data_gate.py --path data/train_m1_clean.csv --json`

План: `docs/Rina_todo.md`.
