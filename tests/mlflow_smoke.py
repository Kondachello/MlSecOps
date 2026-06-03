"""tests/mlflow_smoke.py — end-to-end: логин в бэкенде → MLflow через auth-прокси.

Требует запущенными:
  - MLflow server на :5000 (mlflow server --host 127.0.0.1 --port 5000 ...)
  - Backend (Gatekeeper) на :8000 (uvicorn src.api.main:app), включает /mlflow прокси.

Запуск: python tests/mlflow_smoke.py
"""
from __future__ import annotations

import os

import requests

BACKEND = os.getenv("BACKEND_URL", "http://127.0.0.1:8000")
USER = os.getenv("SMOKE_USER", "msecops")
PASSWORD = os.getenv("SMOKE_PASSWORD", "admin-pass")


def main() -> None:
    # 1) Логин в бэкенде → JWT
    r = requests.post(f"{BACKEND}/api/v1/auth/login",
                      json={"username": USER, "password": PASSWORD})
    r.raise_for_status()
    token = r.json()["access_token"]
    print(f"1) login {USER}: ok, токен получен")

    # 2) Прокси без токена → 401 (доступ к MLflow закрыт для неаутентифицированных)
    anon = requests.post(f"{BACKEND}/mlflow/api/2.0/mlflow/experiments/search",
                         json={"max_results": 1})
    print(f"2) /mlflow без токена -> {anon.status_code} (ожидаем 401)")

    # 3) Настроить MLflow-клиент на прокси (как сниппет из личного кабинета)
    os.environ["MLFLOW_TRACKING_URI"] = f"{BACKEND}/mlflow"
    os.environ["MLFLOW_TRACKING_TOKEN"] = token
    import mlflow
    from mlflow.tracking import MlflowClient

    mlflow.set_experiment("proxy_demo")
    with mlflow.start_run(run_name="smoke") as run:
        mlflow.log_param("lr", 0.01)
        mlflow.log_metric("accuracy", 0.93)
        mlflow.log_text("hello from notebook", "note.txt")  # артефакт через прокси
        rid = run.info.run_id
    print(f"3) залогирован run {rid} через прокси (param+metric+artifact)")

    # 4) Прочитать обратно из MLflow (тоже через прокси) — подтверждение
    c = MlflowClient()
    got = c.get_run(rid)
    print(f"4) readback: params={dict(got.data.params)} metrics={dict(got.data.metrics)}")
    arts = [a.path for a in c.list_artifacts(rid)]
    print(f"   артефакты: {arts}")

    ok = (got.data.params.get("lr") == "0.01"
          and abs(got.data.metrics.get("accuracy", 0) - 0.93) < 1e-9)
    print(f"\nИТОГ: {'OK — MLflow работает через наш auth-прокси' if ok else 'ОШИБКА'}")


if __name__ == "__main__":
    main()
