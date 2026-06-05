"""gates/g8_quality.py — G8: ML quality holdout на ONNX-модели.

ЛОГИКА:
  1. Найти model.onnx в work_dir → если нет → SKIP (G8 применим только к ONNX).
  2. Найти holdout-CSV (`holdout.csv`, `test.csv`) или взять основной dataset.csv → 20% tail.
  3. Прогнать модель через onnxruntime, посчитать accuracy.
  4. FAIL если:
     - accuracy < MIN_ACCURACY (0.55)
     - model предсказывает только один класс (degenerate)
     - есть NaN в выходах

  Если onnxruntime/pandas/numpy не установлены или модели нет → SKIP (не FAIL).

Контракт с DS:
  Чтобы G8 работал, разработчик должен залогировать:
    mlflow.log_artifact("model.onnx")      # модель в ONNX
    mlflow.log_artifact("holdout.csv")     # тестовая выборка с колонкой 'target'
  Иначе G8 отдаст SKIP с пояснением.
"""
from __future__ import annotations

from pathlib import Path

from gates.base import GateContext, GateResult, log_line, register_gate

MIN_ACCURACY = 0.55
MIN_CLASSES = 2
TARGET_CANDIDATES = ("target", "y", "label", "class")


def _find_onnx(work_dir: Path) -> Path | None:
    files = sorted(work_dir.rglob("*.onnx"))
    return files[0] if files else None


def _find_holdout(work_dir: Path) -> Path | None:
    for name in ("holdout.csv", "test.csv", "validation.csv", "valid.csv"):
        p = next(iter(work_dir.rglob(name)), None)
        if p:
            return p
    # Fallback: основной CSV (DATA gate его обычно нашёл).
    csvs = sorted(work_dir.rglob("*.csv"))
    return csvs[0] if csvs else None


@register_gate("G8", name="ML quality", order=50,
               description="ONNX holdout accuracy / degenerate-predictor check",
               severity="high", threats=["#17", "#20"])
def run(ctx: GateContext) -> GateResult:
    gid, gname = "G8", "ML quality"
    logs = [log_line(gid, gname, "поиск ONNX-модели и holdout-датасета")]

    onnx_path = _find_onnx(ctx.work_dir)
    if onnx_path is None:
        logs.append(log_line(gid, gname,
            "SKIP: model.onnx не найден (G8 применим только к ONNX; "
            "DS должен залогировать ONNX-версию модели через mlflow.log_artifact)"))
        return GateResult(id=gid, name=gname, status="SKIP",
                          detail="ONNX-модели нет — G8 применим только к ONNX.",
                          logs=logs, evidence={"reason": "no_onnx"})

    holdout = _find_holdout(ctx.work_dir)
    if holdout is None:
        logs.append(log_line(gid, gname, "SKIP: нет holdout-CSV"))
        return GateResult(id=gid, name=gname, status="SKIP",
                          detail="Не найден holdout.csv / test.csv.",
                          logs=logs, evidence={"reason": "no_holdout"})

    # Ленивые импорты — onnxruntime тяжёлый, нет смысла грузить, если ONNX нет.
    try:
        import numpy as np
        import onnxruntime as ort
        import pandas as pd
    except ImportError as e:
        logs.append(log_line(gid, gname, f"SKIP: deps unavailable: {e}"))
        return GateResult(id=gid, name=gname, status="SKIP",
                          detail=f"Не установлены onnxruntime/numpy/pandas: {e}",
                          logs=logs, evidence={"reason": "deps_missing"})

    logs.append(log_line(gid, gname, f"onnx: {onnx_path.name}"))
    logs.append(log_line(gid, gname, f"holdout: {holdout.name}"))

    try:
        df = pd.read_csv(holdout)
    except Exception as e:  # noqa: BLE001
        logs.append(log_line(gid, gname, f"FAIL: чтение holdout: {e}"))
        return GateResult(id=gid, name=gname, status="FAIL",
                          detail=f"holdout нечитаем: {e}",
                          logs=logs, evidence={"error": str(e)})

    target_col = next((c for c in TARGET_CANDIDATES if c in df.columns), None)
    if target_col is None:
        logs.append(log_line(gid, gname,
            f"SKIP: нет target-колонки {TARGET_CANDIDATES} (есть: {list(df.columns)[:8]})"))
        return GateResult(id=gid, name=gname, status="SKIP",
                          detail=f"В holdout нет ни одной из колонок {TARGET_CANDIDATES}.",
                          logs=logs, evidence={"columns": list(df.columns)})

    y = df[target_col].values
    X_df = df.drop(columns=[target_col])

    # Если это «основной датасет» (не отдельный holdout) — берём хвост 20% как тест.
    if holdout.name not in {"holdout.csv", "test.csv", "validation.csv", "valid.csv"}:
        n = len(df)
        split = max(1, int(n * 0.8))
        X_df = X_df.iloc[split:]
        y = y[split:]
        logs.append(log_line(gid, gname,
            f"используем хвост 20% основного CSV ({len(y)} строк)"))

    if len(y) < 2:
        logs.append(log_line(gid, gname, "SKIP: holdout слишком маленький"))
        return GateResult(id=gid, name=gname, status="SKIP",
                          detail=f"holdout всего {len(y)} строк.",
                          logs=logs, evidence={"n_test": int(len(y))})

    try:
        sess = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])
        input_meta = sess.get_inputs()[0]
        # ONNX-модель может ждать (N, n_features) float32 — конвертируем безопасно
        X = X_df.values.astype(np.float32)
        if len(input_meta.shape) == 2 and X.shape[1] != input_meta.shape[1]:
            logs.append(log_line(gid, gname,
                f"FAIL: schema mismatch — модель ждёт {input_meta.shape[1]} фич, в holdout {X.shape[1]}"))
            return GateResult(id=gid, name=gname, status="FAIL", severity="high",
                              detail=f"Schema mismatch: {input_meta.shape[1]} vs {X.shape[1]}.",
                              logs=logs,
                              evidence={"expected": int(input_meta.shape[1]),
                                        "got": int(X.shape[1])})
        raw = sess.run(None, {input_meta.name: X})[0]
    except Exception as e:  # noqa: BLE001
        logs.append(log_line(gid, gname, f"FAIL: onnxruntime inference: {e}"))
        return GateResult(id=gid, name=gname, status="FAIL", severity="high",
                          detail=f"ONNX inference сломалась: {e}",
                          logs=logs, evidence={"error": str(e)})

    # raw может быть (N,) или (N,1) или (N,C). Приведём к классу.
    arr = np.asarray(raw)
    if arr.ndim > 1 and arr.shape[1] > 1:
        pred = arr.argmax(axis=1).astype(np.int64)
    else:
        flat = arr.flatten()
        pred = (flat >= 0.5).astype(np.int64) if flat.dtype.kind == "f" else flat.astype(np.int64)

    if np.isnan(pred.astype(np.float32)).any():
        logs.append(log_line(gid, gname, "FAIL: NaN в предсказаниях"))
        return GateResult(id=gid, name=gname, status="FAIL", severity="high",
                          detail="ONNX выдаёт NaN.", logs=logs, evidence={"nan": True})

    acc = float((pred == y).mean())
    n_classes_pred = int(len(set(pred.tolist())))
    logs.append(log_line(gid, gname, f"accuracy={acc:.3f}, классов в предикте: {n_classes_pred}"))

    if n_classes_pred < MIN_CLASSES:
        logs.append(log_line(gid, gname, "FAIL: degenerate predictor (один класс)"))
        return GateResult(id=gid, name=gname, status="FAIL", severity="high",
                          detail=f"Модель предсказывает только {n_classes_pred} класс — degenerate.",
                          logs=logs,
                          evidence={"accuracy": acc, "n_classes_pred": n_classes_pred,
                                    "n_test": int(len(y))})

    if acc < MIN_ACCURACY:
        logs.append(log_line(gid, gname, f"FAIL: accuracy < {MIN_ACCURACY}"))
        return GateResult(id=gid, name=gname, status="FAIL", severity="high",
                          detail=f"accuracy {acc:.3f} < {MIN_ACCURACY}",
                          logs=logs,
                          evidence={"accuracy": acc, "min_accuracy": MIN_ACCURACY,
                                    "n_test": int(len(y))})

    logs.append(log_line(gid, gname, f"PASS: accuracy={acc:.3f}"))
    return GateResult(id=gid, name=gname, status="PASS",
                      detail=f"OK: accuracy {acc:.3f} ≥ {MIN_ACCURACY} ({len(y)} строк теста).",
                      logs=logs,
                      evidence={"accuracy": acc, "n_test": int(len(y)),
                                "n_classes_pred": n_classes_pred,
                                "onnx_file": onnx_path.name})
