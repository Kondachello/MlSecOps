"""train.py — обучение модели В CI (эталон для модели №1: табличный credit/fraud scoring).

КОНТРАКТ ВЫХОДА (его читает .github/workflows/train.yml от участника B):
  - артефакт в G4-разрешённом формате → artifacts/<model>.onnx   (allow-list: .onnx/.safetensors/.cbm/.txt)
  - artifacts/model_path.txt  — путь к артефакту
  - artifacts/run_id.txt      — MLflow run_id

КРИТИЧНО: фичи считаются ТОЛЬКО через src.common.features (парность с serve, #19).
НЕЛЬЗЯ сохранять .pkl/.joblib — G4 заблокирует (by design).

Модели №2/№3 (C): сделать аналоги (CNN→.safetensors/.onnx, текст→.onnx) по этому же контракту.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.common.features import FEATURE_NAMES, featurize_df  # noqa: E402

ARTIFACT_DIR = ROOT / os.getenv("MODEL_ARTIFACT_DIR", "artifacts")


def _load_dataset(name: str, version: str):
    """Загрузить ПРОВЕРЕННЫЙ датасет.

    В CI: тянуть из реестра/MinIO по (name, version). Для локального прогона — из data/.
    TODO(C/A): заменить на загрузку governed-копии из MinIO по версии.
    """
    import pandas as pd

    candidate = ROOT / "data" / f"{name}.csv"
    if not candidate.exists():
        candidate = ROOT / "data" / "train_m1_clean.csv"  # fallback для локального демо
    return pd.read_csv(candidate)


def train(model_name: str, dataset_name: str, dataset_version: str,
          git_commit: str, data_source_type: str) -> dict:
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    df = _load_dataset(dataset_name, dataset_version)

    X = featurize_df(df)                 # фичи — ТОЛЬКО через common.features
    y = df["target"].astype(int).values

    # --- обучение (sklearn) ---
    from sklearn.linear_model import LogisticRegression

    clf = LogisticRegression(max_iter=1000)
    clf.fit(X, y)
    acc = float(clf.score(X, y))

    # --- экспорт в ONNX (G4-разрешённый формат, НЕ pickle) ---
    artifact_path = ARTIFACT_DIR / f"{model_name}.onnx"
    try:
        from skl2onnx import to_onnx

        onx = to_onnx(clf, X[:1])
        artifact_path.write_bytes(onx.SerializeToString())
    except Exception as e:  # noqa: BLE001
        print(f"[train] ОШИБКА экспорта ONNX: {e}\n"
              f"        Установи: pip install scikit-learn skl2onnx onnx onnxruntime", file=sys.stderr)
        raise

    # --- MLflow (graceful: нет MLflow → продолжаем, run_id пустой) ---
    run_id = ""
    try:
        import mlflow
        import mlflow.data

        mlflow.set_tracking_uri(os.getenv("MLFLOW_TRACKING_URI", ""))
        with mlflow.start_run() as run:
            ds = mlflow.data.from_pandas(df, source=f"{dataset_name}@{dataset_version}",
                                         name=dataset_name)
            mlflow.log_input(ds, context="training")
            mlflow.log_param("features", FEATURE_NAMES)
            mlflow.log_metric("accuracy", acc)
            mlflow.set_tags({
                "security.git_commit": git_commit,
                "security.data_source_type": data_source_type,
                "security.trained_in_ci": "true",
            })
            run_id = run.info.run_id
    except Exception as e:  # noqa: BLE001
        print(f"[train] MLflow недоступен ({e}) — продолжаю без трекинга", file=sys.stderr)

    # --- контракт выхода для train.yml ---
    (ARTIFACT_DIR / "model_path.txt").write_text(str(artifact_path), encoding="utf-8")
    (ARTIFACT_DIR / "run_id.txt").write_text(run_id, encoding="utf-8")

    print(f"[train] OK: {artifact_path}  accuracy={acc:.4f}  run_id={run_id or '-'}")
    return {"artifact": str(artifact_path), "accuracy": acc, "run_id": run_id}


def main() -> None:
    ap = argparse.ArgumentParser(description="Train model in CI (reference: tabular scoring)")
    ap.add_argument("--model-name", default="credit_scoring")
    ap.add_argument("--git-commit", required=True)
    ap.add_argument("--dataset-name", required=True)
    ap.add_argument("--dataset-version", required=True)
    ap.add_argument("--data-source-type", required=True,
                    choices=["local", "internet", "corp_storage", "verified_id"])
    args = ap.parse_args()
    train(args.model_name, args.dataset_name, args.dataset_version,
          args.git_commit, args.data_source_type)


if __name__ == "__main__":
    main()
