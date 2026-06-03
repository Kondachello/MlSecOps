"""train_risk.py — модель №3: transaction risk (расширенный табличный, 6 фич → ONNX).

Задача: мультифакторный скоринг риска (amount, age + производные фичи).
Использует featurize_risk_row из src.common.features (#19 — parность train↔serve).
Артефакт: artifacts/transaction_risk.onnx  (G4-разрешённый формат).

КОНТРАКТ ВЫХОДА (тот же, что train.py):
  - artifacts/transaction_risk.onnx
  - artifacts/model_path.txt
  - artifacts/run_id.txt
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.common.features import RISK_FEATURE_NAMES, featurize_risk_df  # noqa: E402

ARTIFACT_DIR = ROOT / os.getenv("MODEL_ARTIFACT_DIR", "artifacts")


def _load_dataset(dataset_name: str):
    import pandas as pd

    candidate = ROOT / "data" / f"{dataset_name}.csv"
    if not candidate.exists():
        candidate = ROOT / "data" / "train_m1_clean.csv"
    return pd.read_csv(candidate)


def train(model_name: str = "transaction_risk",
          dataset_name: str = "train_m1_clean",
          dataset_version: str = "v1",
          git_commit: str = "local",
          data_source_type: str = "verified_id") -> dict:
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    artifact_path = ARTIFACT_DIR / f"{model_name}.onnx"

    df = _load_dataset(dataset_name)
    X = featurize_risk_df(df)           # 6 фич через common.features
    y = df["target"].astype(int).values

    from sklearn.ensemble import GradientBoostingClassifier

    clf = GradientBoostingClassifier(n_estimators=50, max_depth=3, random_state=42)
    clf.fit(X, y)
    acc = float(clf.score(X, y))

    # ONNX export
    try:
        from skl2onnx import to_onnx

        onx = to_onnx(clf, X[:1])
        artifact_path.write_bytes(onx.SerializeToString())
        print(f"[train_risk] ONNX сохранён: {artifact_path}  accuracy={acc:.4f}  "
              f"features={RISK_FEATURE_NAMES}")
    except Exception as e:  # noqa: BLE001
        print(f"[train_risk] ОШИБКА ONNX: {e}", file=sys.stderr)
        raise

    # MLflow
    run_id = ""
    try:
        import mlflow
        mlflow.set_tracking_uri(os.getenv("MLFLOW_TRACKING_URI", ""))
        with mlflow.start_run() as run:
            mlflow.log_param("features", RISK_FEATURE_NAMES)
            mlflow.log_metric("accuracy", acc)
            mlflow.set_tags({
                "security.git_commit": git_commit,
                "security.data_source_type": data_source_type,
                "security.trained_in_ci": "true",
                "model.type": "transaction_risk",
            })
            run_id = run.info.run_id
    except Exception as e:  # noqa: BLE001
        print(f"[train_risk] MLflow недоступен ({e})", file=sys.stderr)

    (ARTIFACT_DIR / "model_path.txt").write_text(str(artifact_path), encoding="utf-8")
    (ARTIFACT_DIR / "run_id.txt").write_text(run_id, encoding="utf-8")
    return {"artifact": str(artifact_path), "accuracy": acc, "run_id": run_id}


def main() -> None:
    ap = argparse.ArgumentParser(description="Train transaction risk model (#3, GBT→ONNX)")
    ap.add_argument("--model-name", default="transaction_risk")
    ap.add_argument("--git-commit", required=True)
    ap.add_argument("--dataset-name", default="train_m1_clean")
    ap.add_argument("--dataset-version", default="v1")
    ap.add_argument("--data-source-type", default="verified_id",
                    choices=["local", "internet", "corp_storage", "verified_id"])
    args = ap.parse_args()
    train(args.model_name, args.dataset_name, args.dataset_version,
          args.git_commit, args.data_source_type)


if __name__ == "__main__":
    main()
