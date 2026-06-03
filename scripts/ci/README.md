# scripts/ci — обёртки для CI/CD

Три скрипта на этапе 0, без лишних слоёв.

| Скрипт | Назначение |
|--------|------------|
| `run_gate.sh` | Запуск одного гейта: `data`, `code`, `dependency`, `model`, `registry` |
| `build_all_gates.sh` | `docker build` для всех `src/gates/*/Dockerfile` |
| `parse_report.py` | Краткий вывод JSON-отчёта (для логов GHA) |
| `check_local.sh` | Прогон проверок этапа 0 одной командой |

**Windows:** Git Bash или WSL. Пример:

```bash
bash scripts/ci/check_local.sh
```

Подробный план: `docs/Rina_todo.md`.
