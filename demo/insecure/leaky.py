"""DEMO-ФИКСТУРА (НЕ боевой код) — для проверки G2 (gitleaks).

Здесь намеренно лежит ПОДДЕЛЬНЫЙ плейсхолдер «секрета», чтобы показать, как сканер
секретов краснит PR. Это не настоящий ключ и ничего не открывает.
Используется ТОЛЬКО в демо-сценарии 2 (docs/16_DEMO_SCENARIOS.md).
"""

# [приманка #10] — фейковый плейсхолдер, чтобы gitleaks дал detect:
API_KEY = "FAKE-DEMO-PLACEHOLDER-NOT-A-REAL-SECRET-0000"  # noqa: S105  pragma: allowlist secret
DB_PASSWORD = "FAKE-DEMO-PLACEHOLDER-not-real"            # noqa: S105  pragma: allowlist secret


def connect():
    # Никаких реальных подключений/RCE — только демонстрация находки сканера.
    return "demo only"
