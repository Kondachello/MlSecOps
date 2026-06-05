"""examples/demo_train_evil_pickle.py — «плохой» сценарий: G5 FAIL (вредоносный pickle).

Логирует артефакт `evil_model.pkl`, чей __reduce__ вызывает os.system → классический
pickle-эксплойт. При загрузке (`pickle.load`) такая модель выполнила бы произвольную
команду. G5-гейт ловит это через pickletools.genops + чёрный список dangerous opcodes
(REDUCE/GLOBAL/...).

Демо показывает работу гейта против атаки «третий разработчик/cпам-PyPI/HuggingFace
подсунул вредоносные веса под видом обученной модели».

ВАЖНО: pickle сам по себе НЕ выполняется при создании файла. Опасность только при
`pickle.load`. Мы не загружаем его — просто кладём в артефакты, чтобы G5 его засёк.
"""
from __future__ import annotations

import os
import pickle
import tempfile
from pathlib import Path

os.environ.setdefault("MLFLOW_HTTP_REQUEST_TIMEOUT", "15")
os.environ.setdefault("MLFLOW_HTTP_REQUEST_MAX_RETRIES", "2")

import requests

DEV_USER = os.getenv("DEV_USER", "junior")
DEV_PASSWORD = os.getenv("DEV_PASSWORD", "123")
BACKEND = os.getenv("GATEKEEPER_URL", "http://localhost:8200")
EXPERIMENT = f"{DEV_USER}_demo_bad_model"
MODEL_NAME = "demo_evil_pickle"


class Exploit:
    """Эксплойт: при pickle.load этот объект вызовет os.system('echo pwned')."""
    def __reduce__(self):
        return (os.system, ("echo pwned >/tmp/mlsecops_g5_demo_pwned",))


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

    print("[!] Создаю заведомо вредоносный evil_model.pkl с os.system через __reduce__")

    mlflow.set_experiment(EXPERIMENT)
    with mlflow.start_run(run_name=f"{MODEL_NAME}_evil_run") as run:
        mlflow.set_tags({
            "mlflow.user": DEV_USER,
            "model.name": MODEL_NAME,
            "model.description": "ВРЕДОНОСНЫЙ pickle — должен валиться G5",
            "security.model_origin": "external_unknown",
        })
        with tempfile.TemporaryDirectory() as tmp:
            evil_path = Path(tmp) / "evil_model.pkl"
            with evil_path.open("wb") as f:
                pickle.dump(Exploit(), f)
            print(f"  wrote {evil_path.name} ({evil_path.stat().st_size} bytes)")
            mlflow.log_artifact(str(evil_path))
        print(f"\n[ok] run_id={run.info.run_id}")

    print("\nЧто проверить (UI http://localhost:8501):")
    print(f"  1) «Мои артефакты» → {EXPERIMENT} → этот ран")
    print("  2) «Запустить security check» — G5 должен быть FAIL (suspicious pickle opcodes)")
    print("  3) В логах G5 будет видно: 'dangerous_opcodes=[GLOBAL,REDUCE,...]'")
    print("  4) Инцидент с severity=critical → артефакт упадёт в «не прошли проверку»")


if __name__ == "__main__":
    main()
