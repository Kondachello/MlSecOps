# scripts/ci — оркестрация MLSecOps CI

## Workflows

| Workflow | Триггер | Назначение |
|----------|---------|------------|
| **verify.yml** | `verify` / `scan` dispatch, `workflow_dispatch` | Кнопка «Запуск проверки»: G1 (или skip) → G2∥G3∥G5 → cosign → summary |
| **train.yml** | `train` dispatch | RUN после verify (поток A) |
| **deploy.yml** | `deploy` dispatch | Deploy: G2 deploy + trivy + G4 + cosign |
| **ci.yml** | push/PR | Регрессия на фикстурах `demo/` |

## verify — порядок гейтов

1. **Preflight** — датасет `available` (или fast-path `dataset_already_verified=true` → skip G1).
2. **G1** — данные (последовательно, первым).
3. **G2 + G3 + G5** — параллельно после G1 (поток A: G2 на `src/`; поток B: без G2, добавляется **G4** на веса).
4. **cosign** — подпись отчётов и датасета (если задан `COSIGN_PRIVATE_KEY`).
5. **verify-summary.json** — артефакт для UI / бэка.

## Dispatch payload (бэк → GitHub)

```json
{
  "flow": "A",
  "model_name": "credit_scoring",
  "run_id": "abc",
  "git_sha": "deadbeef",
  "dataset_path": "data/train_m1_clean.csv",
  "dataset_already_verified": false,
  "model_card_path": "demo/model_card_complete.json"
}
```

Поток B: `"flow": "B"`, `"model_artifact_path": "path/to/weights.safetensors"`.

## Локальный тест verify

```bash
# Actions → verify → Run workflow → flow A, dataset_already_verified false
```

## Prod-hardening (deploy)

- `cosign_verify_artifacts.sh` — verify после sign (`REQUIRE_COSIGN=true` на проде).
- `generate_sbom.sh` — CycloneDX SBOM в артефактах.
- `worm_upload_prod.sh` — WORM upload (MinIO или `storage_local/`).
- `register_train_artifact.py` — `POST /api/v1/ci/register-model`.
- G2 `--fail-closed` + semgrep обязателен в deploy/ci.
- Dual HITL: `HITL_APPROVALS_HIGH=2` — см. `docs/RESOURCE_SECURITY_MATRIX.md`.

## CI → UI (ingest)

После summary workflow вызывает `push_reports_to_gatekeeper.sh` → `POST /api/v1/ci/ingest-reports`.
Подробнее: [`docs/CI_TO_UI_PIPELINE.md`](../docs/CI_TO_UI_PIPELINE.md).

## Переменные

- `GITHUB_TOKEN`, `GITHUB_REPO`, `GITHUB_REF=kate_merge` — для dispatch из Gatekeeper.
- `COSIGN_PRIVATE_KEY`, `COSIGN_PASSWORD` — подпись (опционально).
- `USE_GATEKEEPER=true`, `GATEKEEPER_URL` — preflight через API (когда реестр готов).
- `vars.GATEKEEPER_URL` + `secrets.CI_INGEST_TOKEN` — ingest отчётов в findings/events.
