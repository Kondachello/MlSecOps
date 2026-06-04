# CI → артефакты → Gatekeeper → UI

## Цепочка

1. **GitHub Actions** — каждый гейт пишет `gate-*.json` и загружает `upload-artifact`.
2. **summary job** — `merge_verify_summary.py` → `*-summary.json` + `build_run_metadata.py`.
3. **Ingest (опционально)** — `push_reports_to_gatekeeper.sh` → `POST /api/v1/ci/ingest-reports`.
4. **Gatekeeper** — `ingest_gate_report` → таблица `findings`, `log_event` → `events`.
5. **UI** — `GET /api/v1/findings`, `GET /api/v1/events`, `GET /api/v1/cicd/runs` (GitHub API).

## Workflows

| Workflow | Summary artifact | Ingest workflow id |
|----------|------------------|-------------------|
| `verify.yml` | `verify-summary` | `verify` |
| `ci.yml` | `ci-gate-summary` | `ci` |
| `train.yml` | `train-summary` | `train` |
| `deploy.yml` | `deploy-summary` | `deploy` |

## Настройка в GitHub

**Repository variables / secrets**

- `GATEKEEPER_URL` — публичный URL Gatekeeper (например `https://mlsec.example.com` или tunnel на `:8000`).
- `USE_GATEKEEPER` — `true` в workflow env (preflight и register через API).

**Secrets**

- `GITHUB_TOKEN` — для dispatch и poll (у бэка).
- `CI_INGEST_TOKEN` — тот же токен в env бэка `CI_INGEST_TOKEN` (защита ingest).
- `COSIGN_*` — опционально для подписи.

**На Gatekeeper**

```env
GITHUB_TOKEN=...
GITHUB_REPO=owner/MlSecOps
CI_INGEST_TOKEN=<same as secret>
```

## Локальная проверка ingest

```bash
curl -X POST http://localhost:8000/api/v1/ci/ingest-reports \
  -H "Content-Type: application/json" \
  -d '{"workflow":"verify","summary":{"passed":true,"gates":[]}}'
```

## UI

- **Находки** — из БД после ingest.
- **CI/CD логи** — из GitHub, если заданы `GITHUB_TOKEN` + `GITHUB_REPO` (роль MLSecOps для RBAC в проде).
