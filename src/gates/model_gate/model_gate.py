"""
model_gate.py — Model Gate: проверка артефакта перед деплоем.

Запуск:
    python src/gates/model_gate.py models/m1.txt
    python src/gates/model_gate.py models/bad_model.pkl      # → FAIL (broken pickle)
    python src/gates/model_gate.py models/malicious.pkl      # → FAIL (malicious payload)

Выходной код: 0 = OK, 1 = FAIL.
"""

import io
import pickletools
import struct
import sys
from pathlib import Path

# ── Опкоды pickle, которые могут исполнять произвольный код ──────────────────
DANGEROUS_OPCODES = {
    b"R",    # REDUCE       — вызов произвольной функции
    b"i",    # INST         — создание экземпляра класса
    b"o",    # OBJ
    b"\x93", # STACK_GLOBAL — import + getattr (Protocol 2+)
    b"c",    # GLOBAL       — import + getattr (Protocol 0/1)
}

# Строки из стандартной библиотеки, которые недопустимы в моделях
DANGEROUS_SYMBOLS = [
    b"os", b"subprocess", b"builtins", b"eval", b"exec",
    b"system", b"popen", b"importlib", b"__import__",
    b"socket", b"shutil", b"ctypes",
]

PICKLE_MAGIC = b"\x80"  # первый байт pickle Protocol 2+
PICKLE_MAGIC_V0 = b"("  # Protocol 0


def check_is_pickle(data: bytes) -> tuple[bool, str]:
    """Проверяет, является ли файл pickle-файлом."""
    if data[:1] in (PICKLE_MAGIC, PICKLE_MAGIC_V0):
        return True, "Файл является pickle (запрещённый формат)"
    # Дополнительная эвристика: pickle Protocol 0 начинается с ascii
    if data[:2] in (b"(d", b"(l", b"(i", b"(c"):
        return True, "Файл является pickle Protocol 0 (запрещённый формат)"
    return False, ""


def check_pickle_payload(data: bytes) -> tuple[bool, str]:
    """
    Разбирает pickle без выполнения кода и ищет опасные опкоды и символы.
    Возвращает (is_dangerous, reason).
    """
    # Проверка опкодов через pickletools
    found_ops = []
    try:
        buf = io.BytesIO(data)
        for opcode, arg, pos in pickletools.genops(buf):
            if opcode.code.encode() in DANGEROUS_OPCODES or \
               opcode.code.encode() in {b"\x93"}:  # STACK_GLOBAL
                found_ops.append(f"опкод '{opcode.name}' на позиции {pos}")
    except Exception:
        pass  # битый pickle — тоже плохо, но обрабатывается отдельно

    if found_ops:
        return True, f"Опасные опкоды: {'; '.join(found_ops)}"

    # Проверка по сырым байтам (быстрый scan)
    for sym in DANGEROUS_SYMBOLS:
        if sym in data:
            return True, f"Обнаружен запрещённый символ: {sym.decode()!r}"

    return False, ""


def check_model_format(path: Path) -> tuple[bool, str]:
    """
    Проверяет формат модели по расширению и сигнатуре.
    Разрешены: .txt (LightGBM), .cbm (CatBoost), .safetensors + .json.
    """
    allowed_extensions = {".txt", ".cbm", ".safetensors", ".json"}
    if path.suffix.lower() not in allowed_extensions:
        return False, f"Расширение '{path.suffix}' не в списке разрешённых {allowed_extensions}"
    return True, ""


# ── Основная проверка ─────────────────────────────────────────────────────────

def gate_check(model_path: Path) -> list[dict]:
    """
    Запускает все проверки. Возвращает список результатов:
    [{"check": str, "status": "PASS"|"FAIL", "detail": str}]
    """
    results = []

    def record(check, passed, detail=""):
        results.append({
            "check":  check,
            "status": "PASS" if passed else "FAIL",
            "detail": detail,
        })

    # 1. Файл существует
    if not model_path.exists():
        record("file_exists", False, f"Файл не найден: {model_path}")
        return results
    record("file_exists", True)

    # 2. Файл не пустой
    size = model_path.stat().st_size
    record("file_not_empty", size > 0, f"Размер: {size} байт")
    if size == 0:
        return results  # дальше нет смысла проверять

    # 3. Формат по расширению
    fmt_ok, fmt_msg = check_model_format(model_path)
    record("allowed_format", fmt_ok, fmt_msg or f"Формат: {model_path.suffix}")

    # 4. Проверка на pickle (по сигнатуре байт, независимо от расширения)
    data = model_path.read_bytes()
    is_pkl, pkl_msg = check_is_pickle(data)
    record("not_pickle", not is_pkl, pkl_msg or "Не pickle")

    # 5. Если pickle — проверяем payload на опасные опкоды
    if is_pkl:
        is_dangerous, danger_msg = check_pickle_payload(data)
        record("no_malicious_payload", not is_dangerous, danger_msg or "Payload чист")

    return results


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(f"Использование: python {sys.argv[0]} <путь_к_модели>")
        sys.exit(1)

    path = Path(sys.argv[1])
    print(f"\n🔍 Model Gate: проверка {path.name}\n")

    results = gate_check(path)

    all_passed = True
    for r in results:
        icon   = "✅" if r["status"] == "PASS" else "❌"
        detail = f"  → {r['detail']}" if r["detail"] else ""
        print(f"  {icon} [{r['status']}] {r['check']}{detail}")
        if r["status"] == "FAIL":
            all_passed = False

    print()
    if all_passed:
        print("✅ GATE PASSED — модель прошла все проверки\n")
        sys.exit(0)
    else:
        print("❌ GATE FAILED — деплой заблокирован\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
