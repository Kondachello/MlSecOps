# scripts/ci — только для GitHub Actions

Локальные обёртки (Windows / bash) удалены: проверки только через push → [Actions](https://github.com/Kondachello/MlSecOps/actions) на **ubuntu-22.04**.

| Файл | Где используется |
|------|------------------|
| `assert_gate_checks.py` | `ci.yml`, `deploy.yml` — SAST/SCA/secrets/trivy не SKIP |
| `install_trivy.sh` | `deploy.yml` — установка Trivy на runner |

Сборка образов гейтов в CI: job **build-gates** → `docker compose -f infra/docker-compose.gates.yml build`.

План работ: `docs/Rina_todo.md`.
