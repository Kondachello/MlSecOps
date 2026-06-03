"""DEMO-ФИКСТУРА (НЕ боевой код) — для проверки G2 (gitleaks + bandit).

Здесь намеренно лежат:
1. ПОДДЕЛЬНЫЙ плейсхолдер «секрета» (gitleaks detect → FAIL, #10)
2. Опасный вызов subprocess с shell=True (bandit B602 HIGH → FAIL, #8)

Это не настоящий ключ и не содержит реальных команд.
Используется ТОЛЬКО в демо-сценарии 2 (docs/16_DEMO_SCENARIOS.md).
"""
import subprocess  # noqa: S404 — demo-only, not deployed

# [приманка #10] — фейковый плейсхолдер, чтобы gitleaks дал detect:
API_KEY = "FAKE-DEMO-PLACEHOLDER-NOT-A-REAL-SECRET-0000"  # pragma: allowlist secret
DB_PASSWORD = "FAKE-DEMO-PLACEHOLDER-not-real"            # pragma: allowlist secret


def connect():
    # Никаких реальных подключений — только демонстрация находки сканера.
    return "demo only"


def demo_unsafe_call(user_input: str) -> str:
    # [приманка SAST #8] — subprocess с shell=True → bandit B602 HIGH severity.
    # В реале так делать НЕЛЬЗЯ (command injection). Только для демо G2.
    result = subprocess.run(  # noqa: S602 -- намеренная приманка SAST
        "echo " + user_input,
        shell=True,  # [SAST-приманка #8] B602 HIGH: shell=True → command injection risk
        capture_output=True,
        text=True,
        timeout=5,
    )
    return result.stdout
