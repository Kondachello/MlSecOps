# 16 — Демо-сценарии

Цель демо (10–15 мин): показать **цельный сквозной флоу** в динамике + модель угроз, понятную
не только технарям. Всё поднимается одним `docker compose`; сценарии запускаются легко.

## Подготовка
```bash
docker compose -f infra/docker-compose.yml up --build
docker compose -f infra/docker-compose.gates.yml build   # образы гейтов mlsec-gate-*
python data/make_datasets.py            # демо-датасеты: train_m1_clean / _poisoned / prod_traffic_drifted
python demo/insecure/make_model_fixtures.py   # фикстуры моделей: model_safe.safetensors (PASS) / model_unsafe.pkl (FAIL)
# seed первого MLSecOps + демо-пользователей (DS) — из .env
```

**Демо-фикстуры (приманки для гейтов, только в `demo/`):** датасеты — `data/train_m1_poisoned.csv`;
код — `demo/insecure/leaky.py` (секрет→gitleaks, `subprocess(shell=True)`→bandit B602 HIGH);
зависимости — `demo/insecure/requirements.txt` (CVE для pip-audit), `demo/insecure/requirements_vuln.txt`
(typosquat `pytirch`/`tenserflew` для G3); модель — `demo/insecure/model_unsafe.pkl`;
паспорт — `demo/insecure/model_card_incomplete.json` (FAIL) vs `demo/model_card_complete.json` (PASS).

## Сценарий 1 — Загрузка датасета (G1, False Positives)
1. DS загружает датасет (локальный файл / ссылка HF).
2. Запускается G0 (паспорт) + G1 (data gate). Чистый → `available`.
3. Загружаем **приманку** `train_m1_poisoned.csv` (сдвиг баланса классов + колонка `email`).
4. G1 блокирует → датасет в `quarantine`. В UI вкладка «Находки»: причина блока (JSON-evidence:
   `class balance anomaly`, `PII detected`).
5. **False Positive flow:** MLSecOps смотрит причину, при необходимости перенастраивает правило
   и жмёт «Перезапустить проверку» — видна история прогонов.

## Сценарий 2 — Обучение и сборка модели (G2/G3/G4/G5)
1. DS экспериментирует в Jupyter+MLflow (логирует данные/код/модель через прокси).
2. В UI: «Просканировать ресурс» → `/verify` → G5 (lineage) + G2 (код: gitleaks/bandit/pip-audit)
   + G3 (зависимости).
3. Подкладываем **приманки**: `demo/insecure/leaky.py` (секрет→gitleaks, `shell=True`→bandit HIGH),
   `demo/insecure/requirements.txt` (CVE→pip-audit) и `pytirch` из `requirements_vuln.txt` (G3) →
   PR/верификация краснеет, видна причина; неполный `model_card_incomplete.json` → G5 FAIL.
4. После исправления (чистый код + `demo/model_card_complete.json`) — PASS → запускается `train.yml`:
   обучение в CI → G4 на CI-артефакте → регистрация в реестре с lineage (`trained_in_ci=true`).

## Сценарий 3 — Деплой в прод (G4, подписи, Tier/HITL, RBAC)
1. DS жмёт DEPLOY у модели `Tier=HIGH` (кредитный скоринг). Пайплайн **встаёт** — нужен HITL.
2. **RBAC-демо:** DS пытается нажать Approve → `403` + событие «access_denied».
3. MLSecOps делает ручную проверку → Approve (reason) → `deploy.yml`: G2(deploy)+trivy + G4
   (SHA-сверка) + cosign-подпись → проверка подписи+SHA перед `docker run` → alias=`production`.
4. **Подмена артефакта (#4):** руками портим файл в MinIO → деплой падает «hash mismatch».
5. **Внешние веса (поток B):** затягиваем `demo/insecure/model_unsafe.pkl` → G4 блок «unsafe format»;
   берём `demo/model_safe.safetensors` → Tier=HIGH авто → обязательный HITL.

## Сценарий 4 — Атака в проде (G7, мониторинг)
1. Модель в проде, инференс-API работает.
2. `python src/serve/attack_sim.py` — 100 параллельных запросов (эмуляция Model Stealing).
3. API начинает отдавать `429 Too Many Requests`; дашборд показывает всплеск + алерт.
4. Шлём мусорный/огромный payload → `422`/`413` (валидация, лимит).
5. Показываем лог инференса — ПДн **замаскированы** (DLP).
6. (Опц.) подаём `prod_traffic_drifted.csv` → G6: `DRIFT DETECTED: PSI>0.25`.

## Сквозные акценты (показать в любой момент)
- **История событий**: на одном экране — добавлен датасет → скан1 ok → скан2 заблокировал →
  карантин → кто и когда. Актор = реальная личность (не «система»).
- **Целостность лога (#24):** правим строку в `events` руками → верификатор показывает разрыв цепочки.
- **Видимость реестра (#25):** что в проде, чьё, какого Tier, на каких данных/коде обучено (lineage).
- **CEO-вид:** read-only дашборд статуса защищённости.

## Карта сценарий → угрозы
См. [`08_THREAT_MODEL.md`](08_THREAT_MODEL.md) §8.8.
