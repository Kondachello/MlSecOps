"""attack_sim.py — эмуляция Model Stealing / DoS для демо (#5, #6).

Шлёт N параллельных запросов к прод-инференсу. Ожидаемо: сервис начинает отдавать 429,
в дашборде — всплеск + алерт. Никакого вредоносного кода — только нагрузочные запросы
к НАШЕМУ же API. См. docs/16_DEMO_SCENARIOS.md (Сценарий 4).
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import urllib.request

PAYLOAD = {"amount": 100.0, "age": 30, "text": "probe"}


def _one(url: str) -> int:
    data = json.dumps(PAYLOAD).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310 (наш же endpoint)
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:  # noqa: BLE001
        return 0


def main() -> None:
    ap = argparse.ArgumentParser(description="Attack simulation (rate-limit demo)")
    ap.add_argument("--url", default="http://localhost:8080/predict")
    ap.add_argument("--n", type=int, default=200)
    ap.add_argument("--workers", type=int, default=50)
    args = ap.parse_args()

    codes: dict[int, int] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        for code in ex.map(lambda _: _one(args.url), range(args.n)):
            codes[code] = codes.get(code, 0) + 1
    print("Статусы ответов:", dict(sorted(codes.items())))
    print("Ожидаем заметную долю 429 (Too Many Requests) — rate-limit сработал.")


if __name__ == "__main__":
    main()
