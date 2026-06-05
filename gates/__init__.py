"""gates/ — реальные исполняемые security-гейты MLSecOps-платформы.

КОНТРАКТ:
  Каждый гейт — модуль с функцией `run(ctx: GateContext) -> GateResult`.
  Гейты НИЧЕГО не пишут в БД сами — оркестратор (runner.py) собирает результаты и
  отдаёт их бэкенду одним JSON-блоком. Гейты только читают входы и возвращают
  структурированный результат (status + logs[] + detail).

СПИСОК (MVP-набор):
  DATA — PII/poison/nulls в датасете рана  (gates.g_data)
  G0   — секреты в репо/артефактах          (gates.g0_secrets)
  G5   — model artifact scan (pickle)        (gates.g5_modelscan)
  G7   — SHA256 manifest + signature         (gates.g7_sign)
  G8   — ML quality holdout на ONNX          (gates.g8_quality)

ЗАПУСК:
  python -m gates.runner --run-id RUN_ID              # вся цепочка
  python -m gates.runner --run-id RUN_ID --only G5    # один гейт
  python -m gates.runner --run-id RUN_ID --from G5    # с G5 до конца
"""
from gates.base import GateContext, GateResult, GATE_REGISTRY, register_gate  # noqa: F401
