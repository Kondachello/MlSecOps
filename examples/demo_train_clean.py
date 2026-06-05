"""examples/demo_train_clean.py — «хороший» сценарий: все гейты PASS.

Что делает:
  1) Логинится в наш бэкенд (DEV_USER / DEV_PASSWORD), берёт JWT.
  2) Через auth-прокси (`/mlflow`) направляет туда MLflow SDK — владельца штампует сервер.
  3) Обучает sklearn-классификатор на breast_cancer.
  4) Логирует:
     • train.csv + holdout.csv (для DATA-гейта и G8)
     • model.onnx (safe-формат → G5 PASS, G7 подпишет, G8 прогонит holdout)
     • mlflow.log_input(dataset) — lineage данных
     • теги security.* — паспорт безопасности
  5) После этого в UI («Мои артефакты» → этот ран → «Запустить security check»)
     ВСЕ 5 гейтов должны быть PASS.

ЗАПУСК:
  infra\\start.cmd                # поднять стенд (UI :8501, backend :8200, MLflow :5000)
  python examples\\demo_train_clean.py
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

# Таймауты MLflow — ДО import mlflow.
os.environ.setdefault("MLFLOW_HTTP_REQUEST_TIMEOUT", "15")
os.environ.setdefault("MLFLOW_HTTP_REQUEST_MAX_RETRIES", "2")

import requests

DEV_USER = os.getenv("DEV_USER", "kolya1")
DEV_PASSWORD = os.getenv("DEV_PASSWORD", "123")
BACKEND = os.getenv("GATEKEEPER_URL", "http://localhost:8200")
EXPERIMENT = f"{DEV_USER}_demo_clean"
MODEL_NAME = "demo_clean_model"


def login() -> str:
    r = requests.post(f"{BACKEND}/api/v1/auth/login",
                      json={"username": DEV_USER, "password": DEV_PASSWORD}, timeout=10)
    if r.status_code != 200:
        raise SystemExit(f"[ERROR] login {DEV_USER}: {r.status_code} {r.text}\n"
                         f"  Проверь: пользователь существует и имеет роль DS/DE/MLSecOps.")
    print(f"[ok] logged in as {DEV_USER}")
    return r.json()["access_token"]


def main() -> None:
    token = login()
    os.environ["MLFLOW_TRACKING_URI"] = f"{BACKEND}/mlflow"
    os.environ["MLFLOW_TRACKING_TOKEN"] = token

    import mlflow
    import mlflow.data
    import mlflow.sklearn
    import numpy as np
    import pandas as pd
    from sklearn.datasets import load_breast_cancer
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import accuracy_score, roc_auc_score
    from sklearn.model_selection import train_test_split
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler

    df = load_breast_cancer(as_frame=True).frame
    X, y = df.drop(columns="target"), df["target"]
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, stratify=y, random_state=42)

    dataset = mlflow.data.from_pandas(df, name="breast_cancer", targets="target")
    mlflow.set_experiment(EXPERIMENT)

    with mlflow.start_run(run_name=f"{MODEL_NAME}_clean") as run:
        mlflow.log_input(dataset, context="training")
        mlflow.set_tags({
            "mlflow.user": DEV_USER,
            "model.name": MODEL_NAME,
            "model.description": "демо-классификатор (breast cancer, ONNX)",
            "security.data_source_type": "local",
            "security.dataset_origin": "sklearn.datasets.load_breast_cancer",
        })

        clf = make_pipeline(StandardScaler(), LogisticRegression(C=1.0, max_iter=1000))
        clf.fit(Xtr, ytr)
        proba = clf.predict_proba(Xte)[:, 1]
        acc = accuracy_score(yte, clf.predict(Xte))
        auc = roc_auc_score(yte, proba)
        mlflow.log_metric("accuracy", acc)
        mlflow.log_metric("roc_auc", auc)

        # Сохраняем датасеты как артефакты — DATA gate увидит train.csv, G8 — holdout.csv.
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            df.to_csv(tmp_p / "train.csv", index=False)
            pd.concat([Xte, yte], axis=1).to_csv(tmp_p / "holdout.csv", index=False)
            mlflow.log_artifact(str(tmp_p / "train.csv"))
            mlflow.log_artifact(str(tmp_p / "holdout.csv"))

            # ONNX-версия модели — G5 PASS (safe-format), G7 подпишет, G8 прогонит.
            try:
                from skl2onnx import to_onnx
                onnx_model = to_onnx(clf, X.values[:1].astype(np.float32),
                                     target_opset=15)
                (tmp_p / "model.onnx").write_bytes(onnx_model.SerializeToString())
                mlflow.log_artifact(str(tmp_p / "model.onnx"))
                print(f"  saved model.onnx ({(tmp_p / 'model.onnx').stat().st_size} bytes)")
            except ImportError:
                print("  [warn] skl2onnx не установлен — без ONNX гейт G8 будет SKIP")

        # Также пишем sklearn-модель в Model Registry (для версионирования).
        try:
            mlflow.sklearn.log_model(clf, name="model", registered_model_name=MODEL_NAME)
        except TypeError:
            mlflow.sklearn.log_model(clf, artifact_path="model", registered_model_name=MODEL_NAME)

        print(f"\n[ok] run_id={run.info.run_id}  acc={acc:.3f}  roc_auc={auc:.3f}")
        print(f"     experiment={EXPERIMENT}")

    print("\nЧто делать дальше (UI http://localhost:8501):")
    print(f"  1) «Мои артефакты» → {EXPERIMENT} → этот ран")
    print("  2) «Запустить security check» — ВСЕ 5 гейтов должны быть PASS")
    print("  3) «Поделиться» → можно расшарить артефакт (или MLSecOps выкатит в прод)")


if __name__ == "__main__":
    main()
