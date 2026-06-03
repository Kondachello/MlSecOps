"""core/security_check.py — security check артефакта MLflow перед шарингом.

⚠️ ПЛЕЙСХОЛДЕР. Реальная логика гейтов (G0–G7) здесь НЕ реализована — это намеренно.
Сейчас модуль:
  • даёт стабильный контракт результата (passed + список проверок + debug),
  • печатает дебаг-вывод (видно в консоли бэкенда, что проверка реально запускалась),
  • возвращает структуру, которую бэкенд кладёт в artifact_acl.check_detail и в findings.

Запускается ТОЛЬКО по кнопке из ЛК нашего сервиса (не из IDE/ноутбука): разработчик
работает в MLflow, артефакты подтягиваются в сервис, и уже там жмётся «Проверить».

Точки расширения (TODO, когда будем подключать настоящие гейты):
  • G4 Model Gate — формат весов (.safetensors/.onnx/.cbm/.txt; запрет .pkl/.joblib/.bin);
  • скан секретов в тегах/параметрах рана;
  • PII-маркеры в датасете (по mlflow data inputs / Data Digest);
  • lineage: обучено ли в CI, есть ли git_sha/dataset_hash.
"""
from __future__ import annotations

from typing import Optional

# Какие проверки «как будто» прогоняются (для наглядного вывода в UI/консоли).
_PLACEHOLDER_CHECKS = [
    ("model_format", "G4: формат весов (нет .pkl/.joblib/.bin)"),
    ("secret_scan", "Скан секретов в тегах/параметрах рана"),
    ("pii_markers", "PII-маркеры в привязанном датасете"),
    ("lineage", "Lineage: git_sha / dataset_hash / trained_in_ci"),
]


def run_artifact_check(run_id: str, run_meta: Optional[dict] = None) -> dict:
    """Прогнать security check артефакта (ПЛЕЙСХОЛДЕР). Вернуть структурированный результат.

    run_meta — плоский dict рана из mlflow_utils.get_run (теги/параметры/метрики), может быть None.
    Возвращает: {passed, run_id, checks: [{check, status, detail}], debug, placeholder: True}.
    """
    meta = run_meta or {}
    checks = []
    for key, label in _PLACEHOLDER_CHECKS:
        # ПЛЕЙСХОЛДЕР: пока всё «PASS», реальную логику подключим позже.
        checks.append({"check": key, "status": "PASS",
                       "detail": f"{label} — placeholder PASS"})

    passed = all(c["status"] == "PASS" for c in checks)
    result = {
        "passed": passed,
        "run_id": run_id,
        "checks": checks,
        "placeholder": True,
        "debug": {
            "experiment_id": meta.get("experiment_id"),
            "owner": meta.get("owner"),
            "run_name": meta.get("run_name"),
            "n_params": len(meta.get("params", {}) or {}),
            "n_metrics": len(meta.get("metrics", {}) or {}),
            "note": "Логика гейтов не реализована — это заглушка для демонстрации потока.",
        },
    }

    # Дебаг-вывод в консоль бэкенда — видно, что проверка реально запускалась.
    print(f"[security_check] run_id={run_id} owner={meta.get('owner')} "
          f"-> {'PASS' if passed else 'FAIL'} (placeholder)")
    for c in checks:
        print(f"[security_check]   {c['status']:4} {c['check']}: {c['detail']}")

    return result


if __name__ == "__main__":
    # Минимальный пример/демо: прогон проверки на фейковом ране.
    import json
    fake = {"experiment_id": "1", "owner": "vasya", "run_name": "demo-session",
            "params": {"n_estimators": "50"}, "metrics": {"accuracy": 0.93}}
    res = run_artifact_check("run-abc123", fake)
    print("\nРезультат:\n" + json.dumps(res, ensure_ascii=False, indent=2))
