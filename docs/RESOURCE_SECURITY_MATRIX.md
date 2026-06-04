# Матрица безопасности по ресурсам

Единая таблица: **ресурс → проверки → инструмент → стадия → статус в коде**.

Легенда статуса: **✅** реализовано в репо · **⚙️** частично / опционально · **📋** запланировано.

---

## 1. Датасет

| Проверка | Инструмент | Гейт / стадия | Статус |
|----------|------------|---------------|--------|
| Формат CSV/Parquet | pandas | G1 · ingest, verify | ✅ |
| Схема колонок | pandas | G1 | ✅ |
| Типы и диапазоны | pandas | G1 | ✅ |
| Anti-poisoning (баланс) | value_counts | G1 | ✅ |
| Пропуски / дубликаты | pandas | G1 | ✅ |
| PII regex | regex | G1 | ✅ |
| PII ML | Presidio | G1 `pii_presidio` | ⚙️ SKIP без пакета |
| Prompt injection | regex | G1 | ✅ |
| Реестр + quarantine | Postgres/SQLite | `POST /datasets/ingest` | ✅ |
| Verified fast-path | `verified_datasets` | verify skip G1 | ✅ |
| WORM prod lock | MinIO / local | storage | ⚙️ |

**Добавлено:** ingest API с G1 + `mark_dataset_verified`.

---

## 2. Код

| Проверка | Инструмент | Стадия | Статус |
|----------|------------|--------|--------|
| Секреты | gitleaks | G2 ci/deploy | ✅ |
| SAST | bandit (HIGH) | G2 | ✅ |
| ML SAST | semgrep | G2 | ✅ в CI (обязателен в assert) |
| CVE deps | pip-audit | G2 | ✅ |
| CVE образа | trivy | G2 deploy only | ✅ |
| fail-closed | флаг `--fail-closed` | deploy | ✅ |
| py_compile | Python | ci syntax | ✅ |

---

## 3. Зависимости (supply)

| Проверка | Инструмент | Стадия | Статус |
|----------|------------|--------|--------|
| Typosquat | allow-list | G3 | ✅ |
| Pinning | parser requirements | G3 | ✅ |
| Trusted index | URL whitelist | G3 | ✅ |
| SBOM | CycloneDX (`generate_sbom.sh`) | ci/verify/train/deploy | ✅ |

---

## 4. Веса модели

| Проверка | Инструмент | Стадия | Статус |
|----------|------------|--------|--------|
| Allow-list форматов | extension policy | G4 | ✅ |
| Скан весов | modelscan / picklescan | G4 | ✅ |
| SHA vs реестр | hashlib | G4 deploy | ✅ |
| Подпись | cosign sign+verify | train/deploy | ✅ verify script |
| Consistency train↔serve | pytest | G4 опция | 📋 |

**Deploy:** `REQUIRE_REGISTRY_SHA=true`, cosign verify перед smoke.

---

## 5. Паспорт / реестр

| Проверка | Инструмент | Стадия | Статус |
|----------|------------|--------|--------|
| Model card | registry_gate | G5 verify | ✅ |
| Lineage / Tier | G5 | verify | ✅ |
| Запись в БД | `register_model` | train CI | ✅ |
| Список реестра | `GET /registry` | UI | ✅ |
| Dual HITL | `hitl_approvals` | approve ×2 для HIGH | ✅ |
| Deploy только approved | API + preflight | deploy | ✅ |

Env: `HITL_APPROVALS_HIGH=2`, `HITL_APPROVALS_EXTERNAL=2`, `HITL_APPROVALS_DEFAULT=1`.

---

## 6. Docker-образ

| Проверка | Инструмент | Статус |
|----------|------------|--------|
| Non-root USER | Dockerfile.backend | ✅ |
| trivy CRITICAL/HIGH | deploy G2 | ✅ |
| Smoke /health | deploy job | ✅ |

📋 Image signing (cosign attach), distroless base, K8s admission.

---

## 7. Прод API (рантайм G7)

| Проверка | Инструмент | Статус |
|----------|------------|--------|
| Rate limit | Redis | ✅ |
| Input validation | Pydantic | ✅ |
| Output reduction | serve | ✅ |
| DLP logs | regex mask | ✅ |
| OOD heuristic | serve | ✅ |

📋 mTLS, WAF, corporate SSO.

---

## 8. Мониторинг (G6)

| Проверка | Инструмент | Статус |
|----------|------------|--------|
| PSI drift | numpy/monitor | ✅ |
| Re-hash подмены | monitor | ✅ |

📋 Evidently + алерты 24/7, auto-rollback.

---

## 9. CI/CD мета

| Проверка | Инструмент | Статус |
|----------|------------|--------|
| Gate JSON artifacts | upload-artifact | ✅ |
| Summary + ingest | merge_verify_summary | ✅ |
| cicd/runs UI | GitHub API | ✅ |

См. [`CI_TO_UI_PIPELINE.md`](CI_TO_UI_PIPELINE.md).

---

## 10. Аудит

| Механизм | Статус |
|----------|--------|
| events hash-chain | ✅ |
| findings ingest | ✅ |
| RBAC JWT | ✅ |

---

## Порядок prod-deploy (после доработки)

1. Preflight HITL + SHA из реестра  
2. G2 deploy + trivy (fail-closed, semgrep)  
3. G4 SHA (fail-closed)  
4. cosign sign → **cosign verify**  
5. WORM upload  
6. docker smoke /health  
7. ingest summary → UI  

---

## GitHub secrets / vars

| Имя | Назначение |
|-----|------------|
| `vars.GATEKEEPER_URL` | preflight, register, ingest |
| `secrets.CI_INGEST_TOKEN` | защита CI endpoints |
| `secrets.COSIGN_PRIVATE_KEY` | подпись |
| `secrets.COSIGN_PUBLIC_KEY` | verify (опц.) |
| `secrets.GITHUB_TOKEN` | dispatch + cicd poll |

Для демо без cosign: в workflow временно `REQUIRE_COSIGN: "false"` (не для банка).
