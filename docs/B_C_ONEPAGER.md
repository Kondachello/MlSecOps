# B + C на одной странице (TL;DR)

**Платформа MLSecOps** = «контур безопасности» над ML-процессом: на каждом шаге жизни модели
стоит автопроверка (**Gate**). Прошёл — дальше; не прошёл — блок + видна причина. Плюс история
всех действий и ручное одобрение (HITL) для критичных моделей.

- **A** (в работе): БД, хранилище, авторизация, центральный бэкенд.
- **B** (готово): сами проверки (гейты) + CI/CD-конвейер.
- **C** (готово): 3 ML-модели + защита их API + мониторинг + веб-интерфейс.

### Что делает B — гейты (каждый = свой Docker-образ, контракт «JSON + exit 0/1»)
| Gate | Проверяет | Блокирует | Угрозы |
|---|---|---|---|
| **G1 Data** | данные | дисбаланс классов (отрава), ПДн, инъекции | #1 #2 #11 #15 |
| **G2 Code** | код | секреты (gitleaks), CVE (pip-audit), опасный код (bandit), CVE образа (trivy) | #8 #10 |
| **G3 Supply** | зависимости | typosquatting (`pytirch`), незапиненные версии, чужой источник | #9 #3 |
| **G4 Model** | файл модели | опасный формат (`.pkl`), вирус в весах, несовпадение SHA, нет подписи | #3 #4 #19 #26 |
| **G5 Registry** | паспорт+связность | нет owner/Tier/lineage, заниженный Tier | #20 #23 |

CI: `ci.yml` (все гейты, «чистое PASS / плохое BLOCK») · `train.yml` (G2→обучение→G4→#19→реестр) ·
`deploy.yml` (HITL→G2→trivy→G4 SHA→cosign→WORM→сверка SHA→`docker run`).

### Что делает C — модели, рантайм, мониторинг, UI
- **3 модели** в ONNX (формат из белого списка G4): credit_scoring (8080), text_classifier (8081), transaction_risk (8082).
- **Единая `features.py`** для обучения и инференса → нет training-serving skew (#19), защищено тестом (21 шт.).
- **G7 рантайм:** rate-limit→`429` (#5/#6), валидация→`422` (#11), output-reduction (#5/#13), DLP логов (#12). `attack_sim.py` показывает 429.
- **G6 мониторинг 24/7:** дрейф PSI>0.25 → `DRIFT`, ре-хэш SHA → `ПОДМЕНА МОДЕЛИ` (#14/#4).
- **UI (10 вкладок):** Верификация · Паспорт (Tier-бейдж, lineage) · Реестр · История (+проверка хеш-цепочки) · Находки (причина/FP) · Инструменты→угрозы · Деплой/Approve (HITL, RBAC-403) · Доступы · Дашборд.

### Три стыка, на которых всё держится
1. **Контракт гейта** (JSON+exit) → CI и бэкенд зовут любой гейт одинаково; `evidence` → причина в UI.
2. **Контракт обучения** (B↔C): train-скрипты пишут `model_path.txt`/`run_id.txt`, артефакт в ONNX → `train.yml` гонит G4.
3. **Единые фичи + consistency-тест** (C), встроенный в `train.yml` (B) → гарантия #19.

### Граница с A (пока на фолбэке, переключится автоматически)
история → `logs/events.jsonl` (`audit.py`) · фичи для PSI → `logs/inference_*.jsonl` · UI → моки · `train/deploy.yml` → `curl` к будущим ручкам A с мягкой деградацией.

### Потрогать
`make setup && make demo` — весь B+C сквозь, без A. UI: `APP_DEBUG=true .venv/bin/streamlit run ui/app.py`.

---

## Схема потока

```mermaid
flowchart LR
    DATA["📊 Данные"] -->|загрузка| G1{{"G1 Data\nбаланс·PII·схема"}}
    G1 -- FAIL --> Q[("🗑️ карантин\n+ находка")]
    G1 -- PASS --> CODE["💻 Код в git"]

    CODE --> G2{{"G2 Code\nсекреты·CVE·SAST"}}
    CODE --> G3{{"G3 Supply\nтипосквоттинг·пиннинг"}}
    G2 & G3 -- FAIL --> Q
    G2 & G3 -- PASS --> TRAIN["⚙️ Обучение в CI\n(train_*.py → ONNX)"]

    TRAIN --> G4{{"G4 Model\nформат·скан·SHA·подпись"}}
    G4 -- FAIL --> Q
    G4 -- PASS --> G5{{"G5 Registry\nпаспорт·lineage·Tier"}}
    G5 -- FAIL --> Q
    G5 -- PASS --> REG[("📦 Реестр\nalias=candidate")]

    REG --> HITL{"Tier = HIGH?"}
    HITL -- "да: ждёт Approve\n(MLSecOps)" --> DEPLOY
    HITL -- "нет: авто" --> DEPLOY["🚀 deploy.yml\ntrivy·cosign·WORM\nсверка SHA → docker run"]

    DEPLOY --> PROD["🌐 Прод-API (G7)"]
    PROD --- RL["rate-limit→429\nвалидация→422\noutput-reduction·DLP"]
    PROD --> MON["📡 G6 24/7\nPSI дрейф · ре-хэш подмены"]

    PROD -. фичи .-> LOGS[("logs/inference_*.jsonl")]
    LOGS -.-> MON

    %% сквозное
    G1 & G2 & G3 & G4 & G5 -. evidence .-> FIND[("Находки")]
    FIND --> UI["🖥️ UI: реестр·история·находки·дашборд"]
    MON -. алерт .-> EVT[("Audit Trail\nlogs/events.jsonl → БД A")]
    EVT --> UI

    classDef gate fill:#EEF2FF,stroke:#6366F1,color:#1e1b4b
    classDef bad fill:#FEF2F2,stroke:#EF4444,color:#7f1d1d
    classDef ok fill:#F0FFF4,stroke:#22C55E,color:#14532d
    class G1,G2,G3,G4,G5 gate
    class Q,FIND bad
    class REG,PROD ok
```

### Тот же поток текстом (если mermaid не рендерится)
```
Данные → [G1] → код → [G2]+[G3] → обучение в CI (ONNX) → [G4] → [G5] → реестр
                                                                           │
                                              Tier=HIGH? ── да → HITL Approve (MLSecOps)
                                                          └ нет → авто
                                                                           ▼
                                            deploy (trivy·cosign·WORM·сверка SHA) → docker run
                                                                           ▼
                                              ПРОД-API [G7: 429/422/DLP/output-reduction]
                                                                           ▼
                                              [G6 24/7: PSI-дрейф + ре-хэш подмены]

любой гейт FAIL → карантин + находка(evidence) → видно в UI
все действия → Audit Trail (logs/events.jsonl → БД A) → видно в UI
serve пишет фичи → logs → G6 считает дрейф на живом трафике
```
