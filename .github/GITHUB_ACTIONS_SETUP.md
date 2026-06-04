# GitHub Actions — настройка `main`

## 1. Push кода

Убедитесь, что в репозитории **`Kondachello/MlSecOps`** на ветке **`kate_merge`** лежит содержимое папки `main/` (workflows в `.github/workflows/`).

**PAT для push:** у токена в [Fine-grained / classic PAT](https://github.com/settings/tokens) должен быть scope **`workflow`** (иначе GitHub отклонит push с `.github/workflows/*.yml`). Дополнительно: `repo` (или Contents: Read and write). Токен — только в `main/.env` (`GITHUB_TOKEN=...`), не в URL `git remote`.

```powershell
cd main
$env:GITHUB_TOKEN = (Get-Content .env | Where-Object { $_ -match '^GITHUB_TOKEN=' }) -replace '^GITHUB_TOKEN=',''
git -c "http.extraheader=AUTHORIZATION: bearer $env:GITHUB_TOKEN" push -u origin kate_merge
```

После push автоматически запустится workflow **ci**.

## 2. Secrets и Variables (обязательно для связи с бэкендом)

GitHub → репозиторий → **Settings** → **Secrets and variables** → **Actions**

### Secret (Repository secrets)

| Name | Value |
|------|--------|
| `CI_INGEST_TOKEN` | см. ваш локальный `main/.env` → строка `CI_INGEST_TOKEN=...` |

### Variables (Repository variables)

| Name | Value |
|------|--------|
| `REQUIRE_COSIGN` | `false` |
| `GATEKEEPER_URL` | публичный URL API (ngrok/cloudflare → `:8000`). Пока пусто — **ci** всё равно зелёный, ingest пропускается |

Runner: **GitHub-hosted** (`ubuntu-22.04` в yaml). Self-hosted **не нужен**.

## 3. Локальный `.env` (бэкенд Docker)

```powershell
cd main
.\scripts\setup_stack.ps1
```

Скрипт: `docker compose up`, БД `mlflow`, seed датасетов для preflight, вывод URL и напоминание про GitHub Secret.

| Переменная | Назначение |
|------------|------------|
| `GITHUB_REPO` | `Kondachello/MlSecOps` |
| `GITHUB_TOKEN` | PAT `repo` + `workflow` (UI → dispatch) |
| `GITHUB_REF` | `kate_merge` |
| `CI_INGEST_TOKEN` | = Secret в GitHub |

## 4. Проверка

1. **ci** — все jobs зелёные после push.
2. Локально: http://localhost:8502 (UI), http://localhost:8000/docs (API).
3. **train** (Run workflow): defaults уже заданы; при `GATEKEEPER_URL` + ingest — находки в UI.
4. **deploy** — нужен `train_run_id` из успешного train.

## 5. Ingest с GitHub на localhost

Облачный runner не видит `localhost`. Нужен tunnel, например:

```powershell
ngrok http 8000
```

В Variable `GATEKEEPER_URL` → `https://....ngrok-free.app`
