"""Генератор демо-датасетов: чистые + «приманки» для демонстрации срабатывания гейтов.

Создаёт:
  - train_m1_clean.csv         — чистый (G1 PASS)
  - train_m1_poisoned.csv      — дисбаланс классов + колонка email (G1 FAIL: #1, #2)
  - prod_traffic_drifted.csv   — смещённое распределение (G6 DRIFT: #14)

Приманки — обучающие фикстуры для гейтов. Никакого вредоносного кода.
"""
from __future__ import annotations

from pathlib import Path

OUT = Path(__file__).resolve().parent


def main() -> None:
    try:
        import numpy as np
        import pandas as pd
    except Exception:
        print("Нужны pandas/numpy: pip install pandas numpy")
        return

    rng = np.random.default_rng(42)
    n = 1000

    # Чистый: fraud ~2%
    clean = pd.DataFrame({
        "amount": rng.normal(100, 30, n).round(2),
        "age": rng.integers(18, 80, n),
        "target": (rng.random(n) < 0.02).astype(int),  # ~2% fraud
    })
    clean.to_csv(OUT / "train_m1_clean.csv", index=False)

    # Приманка: дисбаланс (fraud ~50%) + PII (email)
    poisoned = clean.copy()
    poisoned["target"] = (rng.random(n) < 0.5).astype(int)  # сдвиг баланса → #1
    poisoned["email"] = [f"user{i}@example.com" for i in range(n)]  # PII → #2
    poisoned.to_csv(OUT / "train_m1_poisoned.csv", index=False)

    # Дрейф: смещённое распределение amount
    drifted = pd.DataFrame({
        "amount": rng.normal(300, 80, n).round(2),  # сдвиг среднего → PSI↑
        "age": rng.integers(18, 80, n),
        "target": (rng.random(n) < 0.02).astype(int),
    })
    drifted.to_csv(OUT / "prod_traffic_drifted.csv", index=False)

    print("Готово: train_m1_clean.csv, train_m1_poisoned.csv, prod_traffic_drifted.csv")


if __name__ == "__main__":
    main()
