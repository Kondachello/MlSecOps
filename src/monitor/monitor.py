"""G6 Observability — мониторинг прода: дрейф (PSI), деградация, подмена модели.

Закрывает #14 (drift) и усиливает #4 (детект подмены в рантайме).
Работает постоянно (не по кнопке). Результаты — в events/findings + дашборд UI.
См. docs/13_RUNTIME_AND_MONITORING.md §13.4.

Запуск локально (демо):
  python src/monitor/monitor.py --reference data/train_m1_clean.csv \\
                                --current data/prod_traffic_drifted.csv \\
                                --columns amount age
  python src/monitor/monitor.py --check-substitution artifacts/credit_scoring.onnx \\
                                --expected-sha <sha>
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
try:
    from src.common.audit import log_event  # Audit Trail (БД A → иначе JSONL-фолбэк)
except Exception:  # noqa: BLE001
    def log_event(*a, **k):  # graceful, если common недоступен
        pass

PSI_THRESHOLD = 0.25
SUBSTITUTION_ALERT_LEVEL = "critical"
LOG_DIR = ROOT / "logs"

# --------------------------------------------------------------------------- #
#  PSI (Population Stability Index)                                            #
# --------------------------------------------------------------------------- #

def _psi_column(ref_vals, cur_vals, n_bins: int = 10) -> float:
    """Вычислить PSI для одной числовой колонки.

    PSI = Σ (actual% - expected%) * ln(actual% / expected%)
    < 0.10 — стабильно; 0.10–0.25 — умеренный сдвиг; > 0.25 — значительный дрейф.
    """
    import numpy as np

    ref_vals = np.asarray(ref_vals, dtype=float)
    cur_vals = np.asarray(cur_vals, dtype=float)

    # Строим границы корзин по референсному распределению
    _, bin_edges = np.histogram(ref_vals, bins=n_bins)
    # Убеждаемся что все текущие значения покрыты
    bin_edges[0] = min(bin_edges[0], cur_vals.min()) - 1e-9
    bin_edges[-1] = max(bin_edges[-1], cur_vals.max()) + 1e-9

    ref_counts, _ = np.histogram(ref_vals, bins=bin_edges)
    cur_counts, _ = np.histogram(cur_vals, bins=bin_edges)

    ref_pct = ref_counts / max(ref_counts.sum(), 1)
    cur_pct = cur_counts / max(cur_counts.sum(), 1)

    # Избегаем log(0): минимальное значение 1e-4
    ref_pct = np.where(ref_pct == 0, 1e-4, ref_pct)
    cur_pct = np.where(cur_pct == 0, 1e-4, cur_pct)

    psi = float(np.sum((cur_pct - ref_pct) * np.log(cur_pct / ref_pct)))
    return round(psi, 5)


def compute_psi(reference_path: str, current_path: str,
                columns: list[str] | None = None) -> dict:
    """Посчитать PSI для всех числовых колонок.

    Возвращает:
      {"column_psi": {col: psi_val}, "max_psi": float, "drifted": bool,
       "drifted_columns": [col, ...], "threshold": PSI_THRESHOLD}
    """
    try:
        import pandas as pd
    except ImportError:
        return {"error": "pandas не установлен", "drifted": False}

    ref = pd.read_csv(reference_path) if reference_path.endswith(".csv") else pd.read_parquet(reference_path)
    cur = pd.read_csv(current_path) if current_path.endswith(".csv") else pd.read_parquet(current_path)

    numeric_cols = list(ref.select_dtypes(include="number").columns)
    if columns:
        numeric_cols = [c for c in columns if c in numeric_cols]
    if not numeric_cols:
        return {"error": "нет числовых колонок для PSI", "drifted": False}

    col_psi: dict[str, float] = {}
    for col in numeric_cols:
        if col not in cur.columns:
            continue
        col_psi[col] = _psi_column(ref[col].dropna(), cur[col].dropna())

    max_psi = max(col_psi.values()) if col_psi else 0.0
    drifted_cols = [c for c, v in col_psi.items() if v > PSI_THRESHOLD]
    drifted = bool(drifted_cols)

    return {
        "column_psi": col_psi,
        "max_psi": round(max_psi, 5),
        "drifted": drifted,
        "drifted_columns": drifted_cols,
        "threshold": PSI_THRESHOLD,
    }


def _try_evidently_psi(reference_path: str, current_path: str,
                       columns: list[str] | None = None) -> dict | None:
    """Попытаться использовать evidently; возвращает None если не установлен."""
    try:
        import pandas as pd
        from evidently import ColumnMapping
        from evidently.metric_preset import DataDriftPreset
        from evidently.report import Report

        ref = pd.read_csv(reference_path) if reference_path.endswith(".csv") else pd.read_parquet(reference_path)
        cur = pd.read_csv(current_path) if current_path.endswith(".csv") else pd.read_parquet(current_path)

        numeric_cols = list(ref.select_dtypes(include="number").columns)
        if columns:
            numeric_cols = [c for c in columns if c in numeric_cols]
        num_cols_map = ColumnMapping(numerical_features=numeric_cols)

        report = Report(metrics=[DataDriftPreset()])
        report.run(reference_data=ref[numeric_cols],
                   current_data=cur[[c for c in numeric_cols if c in cur.columns]],
                   column_mapping=num_cols_map)
        result = report.as_dict()
        # Достать PSI / share_drifted из evidently-результата
        drift_share = result.get("metrics", [{}])[0].get("result", {}).get("share_of_drifted_columns", 0.0)
        return {
            "evidently": True,
            "drift_share": drift_share,
            "drifted": drift_share > 0,
            "threshold": PSI_THRESHOLD,
        }
    except Exception:  # noqa: BLE001
        return None


# --------------------------------------------------------------------------- #
#  Детект подмены модели (#4)                                                  #
# --------------------------------------------------------------------------- #

def sha256_path(path: str) -> str:
    """SHA-256 файла или директории (детерминированный порядок)."""
    p = Path(path)
    h = hashlib.sha256()
    if p.is_file():
        with p.open("rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
    elif p.is_dir():
        for sub in sorted(p.rglob("*")):
            if sub.is_file():
                with sub.open("rb") as f:
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        h.update(chunk)
    return h.hexdigest()


def check_model_substitution(running_artifact_path: str,
                              expected_sha: str) -> dict:
    """Ре-хэш запущенного артефакта ↔ реестр. Возвращает результат проверки.

    Returns:
      {"substituted": bool, "actual_sha": str, "expected_sha": str,
       "path": str, "alert_level": "critical"|None}
    """
    actual = sha256_path(running_artifact_path)
    match = actual == expected_sha
    return {
        "substituted": not match,
        "actual_sha": actual,
        "expected_sha": expected_sha,
        "path": running_artifact_path,
        "alert_level": SUBSTITUTION_ALERT_LEVEL if not match else None,
        "detail": "SHA совпадает — артефакт не подменён" if match
                  else f"ПОДМЕНА МОДЕЛИ: SHA не совпадает! actual={actual[:16]}... expected={expected_sha[:16]}...",
    }


# --------------------------------------------------------------------------- #
#  Деградация качества (опционально, без меток в проде = stub)                 #
# --------------------------------------------------------------------------- #

def check_quality_degradation(accuracy: float, threshold: float = 0.90) -> dict:
    """Сравнить метрику с порогом. Без меток в проде — возвращает SKIP."""
    if accuracy < 0:
        return {"check": "quality", "status": "SKIP",
                "detail": "метки прод-трафика недоступны"}
    return {
        "check": "quality",
        "status": "FAIL" if accuracy < threshold else "PASS",
        "accuracy": accuracy,
        "threshold": threshold,
        "detail": f"accuracy={accuracy:.3f} {'< порога' if accuracy < threshold else '>= порога'} {threshold}",
    }


# --------------------------------------------------------------------------- #
#  Live-PSI из логов инференса (serve пишет logs/inference_<model>.jsonl)        #
# --------------------------------------------------------------------------- #

def live_psi_from_logs(reference_path: str, model: str,
                       columns: list[str] | None = None) -> dict:
    """Сравнить распределение фич из логов инференса с эталоном (train).

    Читает logs/inference_<model>.jsonl (его пишет serve через common.audit.log_feature).
    Возвращает тот же формат, что compute_psi.
    """
    log_path = LOG_DIR / f"inference_{model}.jsonl"
    if not log_path.exists():
        return {"error": f"нет лог-файла {log_path} (сервис ещё не обрабатывал трафик)",
                "drifted": False}
    try:
        import pandas as pd
    except ImportError:
        return {"error": "pandas не установлен", "drifted": False}

    rows = []
    for line in log_path.read_text(encoding="utf-8").splitlines():
        try:
            rows.append(json.loads(line)["features"])
        except Exception:  # noqa: BLE001
            continue
    if not rows:
        return {"error": "лог инференса пуст", "drifted": False}

    cur = pd.DataFrame(rows)
    tmp = LOG_DIR / f"_live_{model}.csv"
    cur.to_csv(tmp, index=False)
    try:
        return compute_psi(reference_path, str(tmp), columns)
    finally:
        tmp.unlink(missing_ok=True)


# --------------------------------------------------------------------------- #
#  CLI                                                                         #
# --------------------------------------------------------------------------- #

def _run_once(args) -> dict:
    """Один цикл мониторинга. Возвращает report; пишет алерты в Audit Trail."""
    report: dict = {}

    if args.live_model:
        report["drift"] = live_psi_from_logs(args.reference, args.live_model, args.columns)
    elif args.reference and args.current:
        ev = _try_evidently_psi(args.reference, args.current, args.columns)
        report["drift"] = ev or compute_psi(args.reference, args.current, args.columns)

    d = report.get("drift")
    if d and d.get("drifted"):
        msg = (f"DRIFT DETECTED: max_psi={d.get('max_psi', '?')} "
               f"cols={d.get('drifted_columns', [])}")
        print(f"[monitor] ⚠ {msg}")
        log_event("monitor", "MLSecOps", "drift_detected",
                  asset=args.live_model or args.current, result="blocked",
                  details=d)
    elif d and not d.get("error"):
        print(f"[monitor] PSI OK: max_psi={d.get('max_psi', d.get('drift_share', 0))} < {PSI_THRESHOLD}")

    if args.artifact:
        if not args.expected_sha:
            actual = sha256_path(args.artifact)
            report["sha256"] = actual
            print(f"[monitor] SHA-256 артефакта: {actual}")
        else:
            res = check_model_substitution(args.artifact, args.expected_sha)
            report["substitution"] = res
            if res["substituted"]:
                print(f"[monitor] 🚨 {res['detail']}")
                log_event("monitor", "MLSecOps", "substitution_detected",
                          asset=args.artifact, result="blocked", details=res)
            else:
                print(f"[monitor] ✓ {res['detail']}")
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="G6 drift/substitution monitor")
    ap.add_argument("--reference", help="train-датасет (csv/parquet) — эталон распределения")
    ap.add_argument("--current",   help="прод-трафик (csv/parquet)")
    ap.add_argument("--live-model", default=None,
                    help="имя модели: брать прод-трафик из logs/inference_<model>.jsonl")
    ap.add_argument("--columns",   nargs="*", default=None,
                    help="список колонок для PSI (по умолчанию — все числовые)")
    ap.add_argument("--check-substitution", dest="artifact",
                    help="путь к запущенному артефакту для детекта подмены")
    ap.add_argument("--expected-sha", dest="expected_sha", default="",
                    help="эталонный SHA-256 из реестра")
    ap.add_argument("--watch", type=int, default=0,
                    help="режим сервиса: повторять каждые N секунд (0 = разово)")
    ap.add_argument("--json", action="store_true", help="вывод в JSON")
    args = ap.parse_args()

    if not args.reference and not args.artifact and not args.live_model:
        ap.print_help()
        sys.exit(1)

    if args.watch > 0:
        # Постоянный мониторинг (G6 «всегда работает»). Прерывание — Ctrl+C.
        print(f"[monitor] watch-режим: каждые {args.watch}s. Ctrl+C для остановки.")
        try:
            while True:
                _run_once(args)
                time.sleep(args.watch)
        except KeyboardInterrupt:
            print("[monitor] остановлен")
            sys.exit(0)

    report = _run_once(args)
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))

    drift_detected = report.get("drift", {}).get("drifted", False)
    sub_detected = report.get("substitution", {}).get("substituted", False)
    sys.exit(1 if (drift_detected or sub_detected) else 0)


if __name__ == "__main__":
    main()
