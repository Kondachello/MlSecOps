"""train.py — обучение модели В CI (канонический способ получить прод-артефакт).

Запускается из train.yml ПОСЛЕ G2(ci). Логирует данные/модель/метрики в MLflow,
фиксирует lineage и ИБ-теги (личность проставляет сервер/CI, не клиент).
Итоговый CI-артефакт затем проверяет G4 и регистрируется (alias=candidate).

См. docs/05_CANONICAL_FLOW.md §5.3, docs/12_CICD.md (train.yml), docs/17_DATASET_LIFECYCLE.md.
Скелет: структура зафиксирована, обучение конкретной модели — TODO.
"""
from __future__ import annotations

import argparse


def main() -> None:
    ap = argparse.ArgumentParser(description="Train model in CI")
    ap.add_argument("--git-commit", required=True, help="git SHA (из CI)")
    ap.add_argument("--dataset-name", required=True)
    ap.add_argument("--dataset-version", required=True)
    ap.add_argument("--data-source-type", required=True,
                    choices=["local", "internet", "corp_storage", "verified_id"])
    args = ap.parse_args()

    # 1. mlflow.set_tracking_uri(...) (за прокси) + set_experiment(...)
    # 2. загрузить ПРОВЕРЕННЫЙ датасет (по name/version из реестра)
    # 3. ds = mlflow.data.from_pandas(df, source=..., name=...)  → SHA-256 + профиль
    # 4. with mlflow.start_run():
    #       mlflow.log_input(ds, context="training")
    #       model = <train>(...)
    #       mlflow.log_param/metric(...)
    #       mlflow.set_tags({"security.git_commit": args.git_commit,
    #                        "security.data_source_type": args.data_source_type, ...})
    #       mlflow.<flavor>.log_model(model, "model")  # safetensors/onnx-совместимо
    # 5. вывести run_id (CI зафиксирует артефакт, посчитает SHA, прогонит G4, register_model,
    #    alias=candidate, trained_in_ci=true)
    raise NotImplementedError("TODO: реализовать обучение конкретной модели по шагам выше")


if __name__ == "__main__":
    main()
