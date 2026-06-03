"""DEMO-ФИКСТУРА — генерация небезопасных/безопасных артефактов для проверки G4.

Создаёт:
  demo/insecure/model_unsafe.pkl    — пикл-файл (G4 FAIL: blocked format #3)
  demo/model_safe.safetensors       — пустой safetensors (G4 PASS)

Ничего вредоносного — только демо срабатывания гейта формата.
"""
from __future__ import annotations

import pickle  # nosec B301 B403 — демо-фикстура, только сериализация пустого dict
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent  # demo/


def make_unsafe_pkl() -> None:
    out = ROOT / "insecure" / "model_unsafe.pkl"
    # Сериализуем пустой словарь — никакого вредоносного кода, только формат .pkl
    payload = pickle.dumps({})  # nosec B301 B403
    out.write_bytes(payload)
    print(f"Создан: {out} ({len(payload)} байт) — блокируется G4 (формат .pkl)")


def make_safe_safetensors() -> None:
    """Минимальный валидный safetensors-файл (пустая карта тензоров)."""
    out = ROOT / "model_safe.safetensors"
    # safetensors format: 8 bytes LE uint64 (header length) + JSON header
    header = b"{}"
    header_len = struct.pack("<Q", len(header))
    out.write_bytes(header_len + header)
    print(f"Создан: {out} — проходит G4 (формат .safetensors)")


if __name__ == "__main__":
    make_unsafe_pkl()
    make_safe_safetensors()
