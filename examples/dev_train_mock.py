"""dev_train_mock.py — простой «ноутбук разработчика»: версионирование модели через MLflow.

Что делает (имитация работы DS в Jupyter):
  1) логинится в НАШ сервис (получает JWT);
  2) настраивает MLflow на наш auth-прокси (`/mlflow`) — это КЛЮЧЕВОЙ момент: личность,
     владельца и теги проставляет СЕРВЕР, поэтому артефакт корректно попадает в наш сервис
     и виден под твоим аккаунтом (а не под именем ОС);
  3) обучает одну модель НЕСКОЛЬКО раз (v1, v2, v3 с разным C) и регистрирует версии в
     MLflow Model Registry — видно, как идёт ВЕРСИОНИРОВАНИЕ модели;
  4) каждый прогон (run) = «сессия» — появляется в нашем UI («Реестр» / «Мои артефакты»).

Версионирование ДАННЫХ — через `mlflow.log_input` (Data Digest = SHA содержимого датасета).

ВАЖНО: логируем ТОЛЬКО через прокси (через :8200/mlflow), НЕ напрямую в MLflow :5000 —
иначе артефакт не получит владельца и «потеряется» в реестре.

ЗАПУСК:
  1) подними стенд:  .\\infra\\start.cmd   (UI :8501, backend :8200, MLflow :5000)
  2) в UI залогинься msecops/admin-pass; при необходимости заведи DEV_USER и выдай ему роль DS;
  3) python examples/dev_train_mock.py
  4) смотри: UI «Реестр»/«Мои артефакты» (раны) и версии модели — в MLflow UI / GET /api/v1/models.
"""
from __future__ import annotations

import os

# Таймауты MLflow задаём ДО import mlflow (иначе при недоступном MLflow клиент висит ~2 мин).
os.environ.setdefault("MLFLOW_HTTP_REQUEST_TIMEOUT", "15")
os.environ.setdefault("MLFLOW_HTTP_REQUEST_MAX_RETRIES", "2")

import requests

# ─────────────────────────── НАСТРОЙКИ ───────────────────────────
DEV_USER = "msecops"            # этот юзер должен существовать и иметь роль (DS/MLSecOps)
DEV_PASSWORD = "admin-pass"
BACKEND = os.getenv("GATEKEEPER_URL", "http://localhost:8200")
EXPERIMENT = f"{DEV_USER}_demo"     # эксперимент = «проект» разработчика
MODEL_NAME = "demo_model"           # имя в MLflow Model Registry; версии копятся под ним
PARAMS_C = [0.01, 0.1, 1.0]         # три прогона → три версии модели


def login() -> str:
    try:
        r = requests.post(f"{BACKEND}/api/v1/auth/login",
                          json={"username": DEV_USER, "password": DEV_PASSWORD}, timeout=10)
    except requests.exceptions.RequestException as e:
        raise SystemExit(f"[ОШИБКА] Бэкенд недоступен на {BACKEND}: {e}")
    if r.status_code != 200:
        raise SystemExit(f"[ОШИБКА] Логин {DEV_USER}: {r.status_code} {r.text}\n"
                         f"  Проверь: пользователь заведён и ему выдана роль.")
    print(f"[ok] вошёл как {DEV_USER}")
    return r.json()["access_token"]


def main() -> None:
    token = login()
    # ВСЁ через прокси: сервер проставит владельца (mlsecops.owner), теги и доступы.
    os.environ["MLFLOW_TRACKING_URI"] = f"{BACKEND}/mlflow"
    os.environ["MLFLOW_TRACKING_TOKEN"] = token

    import mlflow
    import mlflow.data
    import mlflow.sklearn
    from sklearn.datasets import load_breast_cancer
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import accuracy_score, roc_auc_score
    from sklearn.model_selection import train_test_split
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler

    df = load_breast_cancer(as_frame=True).frame           # маленький встроенный датасет
    X, y = df.drop(columns="target"), df["target"]
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, stratify=y, random_state=42)
    dataset = mlflow.data.from_pandas(df, name="breast_cancer", targets="target")  # версия данных = digest

    mlflow.set_experiment(EXPERIMENT)
    print(f"[..] эксперимент '{EXPERIMENT}', обучаю {len(PARAMS_C)} версии модели '{MODEL_NAME}'\n")
    for ver, C in enumerate(PARAMS_C, start=1):
        with mlflow.start_run(run_name=f"{MODEL_NAME}_v{ver}") as run:
            mlflow.log_input(dataset, context="training")          # lineage данных (версия = digest)
            mlflow.set_tags({
                "mlflow.user": DEV_USER,
                "security.data_source_type": "local",
                "model.name": MODEL_NAME,
                "model.purpose": "демо-классификатор (breast cancer)",
                "model.version_hint": f"v{ver}",
            })
            mlflow.log_param("C", C)
            clf = make_pipeline(StandardScaler(), LogisticRegression(C=C, max_iter=1000))
            clf.fit(Xtr, ytr)
            proba = clf.predict_proba(Xte)[:, 1]
            acc = accuracy_score(yte, clf.predict(Xte))
            auc = roc_auc_score(yte, proba)
            mlflow.log_metric("accuracy", acc)
            mlflow.log_metric("roc_auc", auc)
            # Регистрируем версию в MLflow Model Registry (через прокси) → версионирование.
            mlflow.sklearn.log_model(clf, artifact_path="model", registered_model_name=MODEL_NAME)
            print(f"  v{ver}: C={C:<5} accuracy={acc:.3f} roc_auc={auc:.3f}  run={run.info.run_id[:8]}")

    # Показать версии модели из реестра MLflow (видно версионирование).
    try:
        models = requests.get(f"{BACKEND}/api/v1/models",
                              headers={"Authorization": f"Bearer {token}"}, timeout=15).json().get("models", [])
        print("\n[ok] модели в MLflow Registry:")
        for m in models:
            print(f"   {m['name']} — версии: {m.get('latest_versions')}")
    except requests.exceptions.RequestException:
        pass

    print("\nГотово. В UI (http://localhost:8501):")
    print("  • «Реестр» / «Мои артефакты» — три рана-сессии (зона «черновики», пока без проверки);")
    print("  • запусти по ним security check → попадут в зону «прошли проверку»;")
    print("  • версии модели смотри в MLflow UI (http://localhost:5000) и в GET /api/v1/models.")


if __name__ == "__main__":
    main()
