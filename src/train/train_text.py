"""train_text.py — модель №2: текстовый классификатор (TF-IDF + LogReg → ONNX).

Задача: binary spam/not-spam (или toxicity) по коротким текстам.
Артефакт: artifacts/text_classifier.onnx  (G4-разрешённый формат).
Обучается на синтетических данных (без внешнего датасета) для локального демо.

КОНТРАКТ ВЫХОДА (тот же, что у train.py, читает train.yml B):
  - artifacts/text_classifier.onnx
  - artifacts/model_path.txt  ← путь
  - artifacts/run_id.txt      ← MLflow run_id

КРИТИЧНО: фичи через src.common.features.featurize_text (парность с serve, #19).
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.common.features import featurize_texts  # noqa: E402

ARTIFACT_DIR = ROOT / os.getenv("MODEL_ARTIFACT_DIR", "artifacts")

# Синтетический датасет (для демо без внешних данных)
SPAM_EXAMPLES = [
    "you won a free iphone click now", "claim your prize today free money",
    "earn 1000 dollars working from home", "buy cheap pills online best price",
    "win a cruise ship trip limited time", "get rich quick guaranteed income",
    "click here to unsubscribe now spam", "approve this loan immediately urgent",
    "hot singles in your area tonight", "free casino bonus no deposit needed",
    "limited offer act now discount sale", "credit card debt relief program",
    "lose weight fast guaranteed results", "investment opportunity high returns",
    "you have been selected winner prize",
]
HAM_EXAMPLES = [
    "meeting tomorrow at 10am in room 3", "please review the pull request",
    "the quarterly report is attached", "can we reschedule to friday",
    "thanks for your help with the project", "the deployment went smoothly",
    "security review completed all gates pass", "model training finished accuracy 0.98",
    "new dataset uploaded to the registry", "please approve the deploy request",
    "the monitor detected no drift today", "audit log verified all events ok",
    "data governance policy updated", "mlflow run completed successfully",
    "please add me to the review thread",
]


def _make_dataset():
    texts = [featurize_texts(SPAM_EXAMPLES), featurize_texts(HAM_EXAMPLES)]
    X = texts[0] + texts[1]
    y = [1] * len(texts[0]) + [0] * len(texts[1])
    return X, y


def train(model_name: str = "text_classifier",
          git_commit: str = "local",
          dataset_name: str = "synthetic_text",
          dataset_version: str = "v1",
          data_source_type: str = "local") -> dict:
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    artifact_path = ARTIFACT_DIR / f"{model_name}.onnx"

    X, y = _make_dataset()

    # Sklearn TF-IDF + LogReg pipeline
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline

    pipe = Pipeline([
        ("tfidf", TfidfVectorizer(max_features=500, ngram_range=(1, 2))),
        ("clf",   LogisticRegression(max_iter=500, C=1.0)),
    ])
    pipe.fit(X, y)
    acc = float(pipe.score(X, y))

    # Экспорт в ONNX через skl2onnx
    try:
        from skl2onnx import to_onnx
        from skl2onnx.common.data_types import StringTensorType

        # Pipeline принимает строки — указываем тип входа
        onx = to_onnx(pipe, initial_types=[("text_input", StringTensorType([None, 1]))])
        artifact_path.write_bytes(onx.SerializeToString())
        print(f"[train_text] ONNX сохранён: {artifact_path}  accuracy={acc:.4f}")
    except Exception as e:  # noqa: BLE001
        print(f"[train_text] ОШИБКА ONNX: {e}\n"
              "  Установи: pip install scikit-learn skl2onnx onnx onnxruntime", file=sys.stderr)
        raise

    # MLflow (graceful)
    run_id = ""
    try:
        import mlflow
        mlflow.set_tracking_uri(os.getenv("MLFLOW_TRACKING_URI", ""))
        with mlflow.start_run() as run:
            mlflow.log_metric("accuracy", acc)
            mlflow.set_tags({
                "security.git_commit": git_commit,
                "security.data_source_type": data_source_type,
                "security.trained_in_ci": "true",
                "model.type": "text_classifier",
            })
            run_id = run.info.run_id
    except Exception as e:  # noqa: BLE001
        print(f"[train_text] MLflow недоступен ({e})", file=sys.stderr)

    (ARTIFACT_DIR / "model_path.txt").write_text(str(artifact_path), encoding="utf-8")
    (ARTIFACT_DIR / "run_id.txt").write_text(run_id, encoding="utf-8")
    return {"artifact": str(artifact_path), "accuracy": acc, "run_id": run_id}


def main() -> None:
    ap = argparse.ArgumentParser(description="Train text classifier (model #2, TF-IDF+LR→ONNX)")
    ap.add_argument("--model-name", default="text_classifier")
    ap.add_argument("--git-commit", required=True)
    ap.add_argument("--dataset-name", default="synthetic_text")
    ap.add_argument("--dataset-version", default="v1")
    ap.add_argument("--data-source-type", default="verified_id",
                    choices=["local", "internet", "corp_storage", "verified_id"])
    args = ap.parse_args()
    train(args.model_name, args.git_commit, args.dataset_name,
          args.dataset_version, args.data_source_type)


if __name__ == "__main__":
    main()
