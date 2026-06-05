"""examples/demo_train_poison_data.py — «плохой» сценарий: DATA gate FAIL (PII).

Логирует датасет с подмешанными номерами банковских карт в одну из колонок.
DATA gate увидит PII-паттерн → FAIL → артефакт упадёт в зону «не прошли проверку»,
будет заведён инцидент с severity=high.

Это демо показывает работу гейта против атаки/недосмотра «слили в обучающий набор
персональные данные клиентов».
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

os.environ.setdefault("MLFLOW_HTTP_REQUEST_TIMEOUT", "15")
os.environ.setdefault("MLFLOW_HTTP_REQUEST_MAX_RETRIES", "2")

import requests

DEV_USER = os.getenv("DEV_USER", "junior")
DEV_PASSWORD = os.getenv("DEV_PASSWORD", "123")
BACKEND = os.getenv("GATEKEEPER_URL", "http://localhost:8200")
EXPERIMENT = f"FF1FFFF{DEV_USER}_demo_bad_data"
MODEL_NAME = "FFFFF1Ffdemo_pii_model"


def login() -> str:
    r = requests.post(f"{BACKEND}/api/v1/auth/login",
                      json={"username": DEV_USER, "password": DEV_PASSWORD}, timeout=10)
    if r.status_code != 200:
        raise SystemExit(f"[ERROR] login {DEV_USER}: {r.status_code} {r.text}")
    return r.json()["access_token"]


def main() -> None:
    token = login()
    os.environ["MLFLOW_TRACKING_URI"] = f"{BACKEND}/mlflow"
    os.environ["MLFLOW_TRACKING_TOKEN"] = token

    import mlflow
    import pandas as pd
    from sklearn.datasets import load_breast_cancer
    from sklearn.linear_model import LogisticRegression

    df = load_breast_cancer(as_frame=True).frame
    # Подмешиваем PII: в первые 5 строк колонки "customer_card" пишем номера карт.
    df.insert(0, "customer_card", "")
    df.loc[:4, "customer_card"] = [
        "4111 1111 1111 1111",   # VISA test
        "5500 0000 0000 0004",   # MC test
        "3400-0000-0000-009",
        "4012888888881881",
        "6011000990139424",
    ]
    print(f"[!] Заведомо плохой датасет: PII в колонке 'customer_card' (5 номеров карт)")

    mlflow.set_experiment(EXPERIMENT)
    with mlflow.start_run(run_name=f"{MODEL_NAME}_pii_run") as run:
        mlflow.set_tags({
            "mlflow.user": DEV_USER,
            "model.name": MODEL_NAME,
            "model.description": "ПЛОХОЙ датасет: содержит PII (номера карт)",
            "security.data_source_type": "unknown",
        })
        # Считаем «модель» (бесполезно, нужно только чтобы был ран).
        clf = LogisticRegression(max_iter=200)
        clf.fit(df.drop(columns=["target", "customer_card"]).values, df["target"].values)
        mlflow.log_metric("accuracy", 0.9)  # не важно — гейт упадёт раньше

        with tempfile.TemporaryDirectory() as tmp:
            train_csv = Path(tmp) / "train_with_pii.csv"
            df.to_csv(train_csv, index=False)
            mlflow.log_artifact(str(train_csv))
        print(f"\n[ok] run_id={run.info.run_id}")

    print("\nЧто проверить (UI http://localhost:8501):")
    print(f"  1) «Мои артефакты» → {EXPERIMENT} → этот ран")
    print("  2) «Запустить security check» — DATA gate должен быть FAIL (PII detected)")
    print("  3) «Инциденты» — должен появиться открытый инцидент с гейтом DATA")
    print("  4) Артефакт упадёт в зону «не прошли проверку» в реестре")


if __name__ == "__main__":
    main()
