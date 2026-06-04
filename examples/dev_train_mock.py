"""dev_train_mock.py — реалистичный «ноутбук разработчика» (ML-исследование).

Имитирует то, что делает DS у себя в IDE/Jupyter: логинится в нашем сервисе, получает
токен, настраивает MLflow на наш auth-прокси и проводит небольшое ИССЛЕДОВАНИЕ —
перебор нескольких моделей на одном датасете. Каждый прогон (run) = «сессия разработки»
(данные + код + модель), которую потом видно в нашем сервисе на вкладке «Мои артефакты».

ML здесь настоящий (sklearn на встроенном датасете breast cancer), но маленький и быстрый.
Модель НЕ сохраняется в pickle (его блокирует G4) — логируем метрики, артефакты-отчёты и
lineage датасета (mlflow.data → Data Digest).

КАК ЗАПУСТИТЬ:
  1) подними стенд:   powershell -ExecutionPolicy Bypass -File infra\\run_local.ps1
  2) в UI (http://localhost:8501) залогинься админом msecops/admin-pass,
     зарегай этого пользователя (см. DEV_USER ниже) и выдай ему роль DS;
  3) запусти:         python examples/dev_train_mock.py
  4) открой в UI вкладку «Мои артефакты» → по каждой сессии: «Запустить security check» → «Поделиться».
"""
from __future__ import annotations

import os

# ВАЖНО: таймауты/ретраи MLflow задаём ДО import mlflow, иначе при недоступном
# MLflow клиент молча ретраит ~2 минуты и выглядит как «вечное зависание».
os.environ.setdefault("MLFLOW_HTTP_REQUEST_TIMEOUT", "10")
os.environ.setdefault("MLFLOW_HTTP_REQUEST_MAX_RETRIES", "2")

import requests

# ─────────────────────────── НАСТРОЙКИ (хардкод) ───────────────────────────
# Креды разработчика к НАШЕМУ сервису (этот юзер должен быть зарегистрирован,
# и MLSecOps должен выдать ему роль DS). Поменяй под своего пользователя.
DEV_USER = "msecops"
DEV_PASSWORD = "admin-pass"
EXPERIMENT = f"{DEV_USER}_research"     # «аккаунт»/эксперимент разработчика

BACKEND = os.getenv("GATEKEEPER_URL", "http://localhost:8200")


def login() -> dict:
    """Войти в наш сервис → заголовки с Bearer-токеном (как кнопка «MLflow-токен» в ЛК)."""
    try:
        r = requests.post(f"{BACKEND}/api/v1/auth/login",
                          json={"username": DEV_USER, "password": DEV_PASSWORD}, timeout=10)
    except requests.exceptions.RequestException as e:
        raise SystemExit(f"[ОШИБКА] Бэкенд недоступен на {BACKEND}. Запущен ли он? ({e})")
    if r.status_code != 200:
        raise SystemExit(
            f"[ОШИБКА] Не удалось войти как {DEV_USER}: {r.status_code} {r.text}\n"
            f"  Проверь: пользователь зарегистрирован и MLSecOps выдал ему роль DS.")
    print(f"[ok] вошёл как {DEV_USER}, токен получен")
    return {"Authorization": f"Bearer {r.json()['access_token']}", "_token": r.json()["access_token"]}


def preflight(headers: dict) -> None:
    """Убедиться, что MLflow доступен через прокси (иначе fail-fast с понятной подсказкой)."""
    print("[..] проверяю доступность MLflow через прокси...", flush=True)
    try:
        pf = requests.post(f"{BACKEND}/mlflow/api/2.0/mlflow/experiments/search",
                           headers={"Authorization": headers["Authorization"]},
                           json={"max_results": 1}, timeout=10)
    except requests.exceptions.RequestException as e:
        raise SystemExit(
            f"[ОШИБКА] MLflow через прокси не отвечает: {e}\n"
            f"  Проще всего: powershell -ExecutionPolicy Bypass -File infra\\run_local.ps1")
    if pf.status_code == 502:
        raise SystemExit("[ОШИБКА] Прокси не достучался до MLflow (502). "
                         "MLflow server на :5000 не запущен? Подними infra\\run_local.ps1")
    if pf.status_code != 200:
        raise SystemExit(f"[ОШИБКА] MLflow-прокси вернул {pf.status_code}: {pf.text[:200]}")
    print("[ok] MLflow доступен")


TARGET = "target"          # целевая колонка
DATASET_ID = "sklearn.datasets.load_breast_cancer"


def make_dataset():
    """Лёгкий встроенный датасет (breast cancer, бинарная классификация) → train/test + фрейм."""
    from sklearn.datasets import load_breast_cancer
    from sklearn.model_selection import train_test_split

    df = load_breast_cancer(as_frame=True).frame   # 569×31, колонка target ∈ {0,1}
    cols = [c for c in df.columns if c != TARGET]
    train_df, test_df = train_test_split(df, test_size=0.25, stratify=df[TARGET],
                                         random_state=42)
    return df, train_df, test_df, cols


def build_models():
    """Сетка экспериментов: каждый элемент станет отдельной сессией (run) в MLflow."""
    from sklearn.linear_model import LogisticRegression
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler

    def logreg(C):  # logreg чувствителен к масштабу — нормируем фичи в пайплайне
        return make_pipeline(StandardScaler(),
                             LogisticRegression(C=C, max_iter=1000, class_weight="balanced"))
    return [
        ("logreg_C0.1", logreg(0.1), {"model": "logreg", "C": 0.1, "class_weight": "balanced"}),
        ("logreg_C1.0", logreg(1.0), {"model": "logreg", "C": 1.0, "class_weight": "balanced"}),
        ("rf_100", RandomForestClassifier(n_estimators=100, max_depth=8, random_state=0),
         {"model": "random_forest", "n_estimators": 100, "max_depth": 8}),
        ("rf_300", RandomForestClassifier(n_estimators=300, max_depth=12, random_state=0),
         {"model": "random_forest", "n_estimators": 300, "max_depth": 12}),
    ]


def main() -> None:
    headers = login()
    preflight(headers)

    # Настроить MLflow-клиент на наш ПРОКСИ — токен едет в заголовке Authorization.
    os.environ["MLFLOW_TRACKING_URI"] = f"{BACKEND}/mlflow"
    os.environ["MLFLOW_TRACKING_TOKEN"] = headers["_token"]
    import mlflow
    import mlflow.data
    from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                                 f1_score, roc_auc_score, confusion_matrix)

    print(f"[..] готовлю датасет и эксперимент '{EXPERIMENT}'...", flush=True)
    full_df, train_df, test_df, feat_cols = make_dataset()
    mlflow.set_experiment(EXPERIMENT)
    # Датасет для lineage: from_pandas сам считает SHA-256 содержимого (Data Digest).
    ds = mlflow.data.from_pandas(full_df, name="breast_cancer", targets=TARGET)

    Xtr, ytr = train_df[feat_cols], train_df[TARGET]
    Xte, yte = test_df[feat_cols], test_df[TARGET]

    print(f"[..] провожу ML-исследование: {len(build_models())} сессий\n", flush=True)
    results = []
    for run_name, clf, params in build_models():
        with mlflow.start_run(run_name=run_name) as run:
            mlflow.log_input(ds, context="training")        # привязка данных к рану (lineage, G5)
            mlflow.log_params(params)
            mlflow.set_tags({                                # ИБ-теги (бэкенд читает их на /verify)
                "mlflow.user": DEV_USER,                     # запасная атрибуция (основная — штамп прокси)
                "security.data_source_type": "local",
                "security.data_path_or_id": DATASET_ID,
                "security.git_commit": os.getenv("GIT_COMMIT", "dev-local"),
                "research.dataset_rows": len(full_df),
                "research.positive_rate": round(float(full_df[TARGET].mean()), 4),
            })

            clf.fit(Xtr, ytr)
            pred = clf.predict(Xte)
            proba = clf.predict_proba(Xte)[:, 1]
            metrics = {
                "accuracy": accuracy_score(yte, pred),
                "precision": precision_score(yte, pred, zero_division=0),
                "recall": recall_score(yte, pred, zero_division=0),
                "f1": f1_score(yte, pred, zero_division=0),
                "roc_auc": roc_auc_score(yte, proba),
            }
            mlflow.log_metrics({k: round(v, 4) for k, v in metrics.items()})

            # Артефакты-отчёты (без pickle — его блокирует G4): метрики + матрица ошибок.
            cm = confusion_matrix(yte, pred)
            mlflow.log_dict({"confusion_matrix": cm.tolist(),
                             "labels": ["class_0", "class_1"]}, "confusion_matrix.json")
            mlflow.log_dict({"params": params,
                             "metrics": {k: round(v, 4) for k, v in metrics.items()}},
                            "model_card.json")

            results.append((run_name, metrics["roc_auc"], run.info.run_id))
            print(f"  [{run_name}]  roc_auc={metrics['roc_auc']:.3f}  "
                  f"f1={metrics['f1']:.3f}  recall={metrics['recall']:.3f}  "
                  f"(run {run.info.run_id[:8]})")

    best = max(results, key=lambda x: x[1])
    print(f"\n[ok] исследование завершено. Лучшая модель: {best[0]} (roc_auc={best[1]:.3f})")
    print(f"     записано {len(results)} сессий в эксперимент '{EXPERIMENT}'\n")
    print("Что дальше — проверь, что всё работает:")
    print(f"  1) UI:  http://localhost:8501  (войди как {DEV_USER}) → вкладка «Мои артефакты»")
    print( "     - увидишь свои сессии; они ПРИВАТНЫ (другой юзер их не видит);")
    print( "     - жми «Запустить security check» (плейсхолдер → PASS), затем «Поделиться»;")
    print( "     - по умолчанию виден ролям с твоим клиренсом и выше; можно задать кастомные роли.")
    print( "  2) MLflow UI: http://localhost:5000  (раны эксперимента)")
    print( "  3) Проверь изоляцию: войди другим DS-юзером — приватные сессии не видны,")
    print( "     а после «Поделиться» появляются у него во вкладке «Доступно мне».")


if __name__ == "__main__":
    main()
