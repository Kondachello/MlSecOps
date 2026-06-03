"""dev_train_mock.py — СУПЕР-ПРОСТОЙ мок «ноутбука разработчика».

Имитирует то, что делает DS у себя: логинится в нашем сервисе, получает токен,
настраивает MLflow на наш auth-прокси и логирует «обучение» (params + metrics +
маленький артефакт). Никакого реального ML — просто числа.

Запуск (после того как MLSecOps выдал тебе роль):
    python examples/dev_train_mock.py --user vasya --password pw123

Затем смотри результат:
    - в нашем UI:    http://localhost:8501  -> вкладка «MLflow раны»
    - в MLflow UI:   http://localhost:5000
"""
from __future__ import annotations

import argparse
import os
import random

# ВАЖНО: таймауты/ретраи MLflow задаём ДО import mlflow, иначе при недоступном
# MLflow клиент молча ретраит ~2 минуты и выглядит как «вечное зависание».
os.environ.setdefault("MLFLOW_HTTP_REQUEST_TIMEOUT", "10")
os.environ.setdefault("MLFLOW_HTTP_REQUEST_MAX_RETRIES", "2")

import requests

BACKEND = os.getenv("GATEKEEPER_URL", "http://localhost:8000")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--user", default="хуй")
    ap.add_argument("--password", default="большой")
    ap.add_argument("--experiment", default="писяпопа")
    args = ap.parse_args()

    # 1) Логин в нашем сервисе → JWT (как кнопка «получить MLflow-токен» в кабинете)
    try:
        r = requests.post(f"{BACKEND}/api/v1/auth/login",
                          json={"username": args.user, "password": args.password}, timeout=10)
    except requests.exceptions.RequestException as e:
        raise SystemExit(f"[ОШИБКА] Бэкенд недоступен на {BACKEND}. Запущен ли он? ({e})")
    if r.status_code != 200:
        raise SystemExit(f"[ОШИБКА] Не удалось войти как {args.user}: {r.status_code} {r.text}\n"
                         f"  Проверь логин/пароль и что MLSecOps выдал тебе роль.")
    token = r.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    print(f"[ok] вошёл как {args.user}, токен получен")

    # 2) ПРЕФЛАЙТ: убедиться, что MLflow доступен через прокси (иначе fail-fast)
    print("[..] проверяю доступность MLflow через прокси...", flush=True)
    try:
        pf = requests.post(f"{BACKEND}/mlflow/api/2.0/mlflow/experiments/search",
                           headers=headers, json={"max_results": 1}, timeout=10)
    except requests.exceptions.RequestException as e:
        raise SystemExit(
            f"[ОШИБКА] MLflow через прокси не отвечает: {e}\n"
            f"  Проверь: 1) запущен ли mlflow server на :5000  "
            f"2) backend стартовал с MLFLOW_UPSTREAM_URL=http://127.0.0.1:5000\n"
            f"  Проще всего: powershell -ExecutionPolicy Bypass -File infra\\run_local.ps1")
    if pf.status_code == 502:
        raise SystemExit("[ОШИБКА] Прокси не достучался до MLflow (502). "
                         "MLflow server на :5000 не запущен? Подними infra\\run_local.ps1")
    if pf.status_code != 200:
        raise SystemExit(f"[ОШИБКА] MLflow-прокси вернул {pf.status_code}: {pf.text[:200]}")
    print("[ok] MLflow доступен")

    # 3) Настроить MLflow-клиент на наш ПРОКСИ — токен едет в заголовке
    os.environ["MLFLOW_TRACKING_URI"] = f"{BACKEND}/mlflow"
    os.environ["MLFLOW_TRACKING_TOKEN"] = token
    import mlflow

    print('[..] логирую "обучение" в MLflow...', flush=True)
    mlflow.set_experiment(args.experiment)

    # 4) «Обучение»: параметры, метрики по эпохам и крошечный артефакт
    with mlflow.start_run(run_name="mock-train") as run:
        mlflow.set_tag("mlflow.user", args.user)          # чтобы личность была видна в UI
        mlflow.log_param("model", "logreg")
        mlflow.log_param("lr", 0.01)
        acc = 0.5
        for epoch in range(5):
            acc += random.uniform(0.02, 0.09)
            mlflow.log_metric("accuracy", round(min(acc, 0.99), 3), step=epoch)
            print(f"  эпоха {epoch}: accuracy={round(min(acc,0.99),3)}")
        mlflow.log_text("это мок-модель, не настоящие веса", "model_note.txt")
        run_id = run.info.run_id

    print(f"\n[ok] залогирован run {run_id} в эксперимент '{args.experiment}'")
    print("Теперь открой:")
    print(f"  наш сайт:  http://localhost:8501  -> вкладка «MLflow раны»")
    print(f"  MLflow UI: http://localhost:5000")


if __name__ == "__main__":
    main()
