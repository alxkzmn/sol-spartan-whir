#!/usr/bin/env python3
"""Verify the fixed-base exponentiation tables used by the native verifiers."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class TableSpec:
    name: str
    base: int
    exponent_bits: int
    windows: int


@dataclass(frozen=True)
class VerifierSpec:
    label: str
    source: Path
    modulus: int
    tables: tuple[TableSpec, ...]


VERIFIERS = (
    VerifierSpec(
        label="BabyBear",
        source=ROOT
        / "src/whir/babybear_k22_jb100_ext5_lir4_ff4_rsv3_pow28/BabyBearWhirVerifierCore5.sol",
        modulus=0x78000001,
        tables=(
            TableSpec("POW_TABLE_ROUND0", 570_250_684, 22, 6),
            TableSpec("POW_TABLE_ROUND1", 1_049_899_240, 19, 5),
            TableSpec("POW_TABLE_ROUND2", 1_559_589_183, 18, 5),
            TableSpec("POW_TABLE_FINAL", 1_286_330_022, 17, 5),
        ),
    ),
    VerifierSpec(
        label="KoalaBear",
        source=ROOT / "src/whir/k22_jb100_ext5_lir4_ff4_rsv3_pow28/WhirVerifierCore5.sol",
        modulus=0x7F000001,
        tables=(
            TableSpec("POW_TABLE_ROUND0", 542_991_299, 22, 6),
            TableSpec("POW_TABLE_ROUND1", 339_671_193, 19, 5),
            TableSpec("POW_TABLE_ROUND2", 1_816_824_389, 18, 5),
            TableSpec("POW_TABLE_FINAL", 373_019_801, 17, 5),
        ),
    ),
    VerifierSpec(
        label="KoalaBear octic",
        source=ROOT / "src/whir/k22_jb100_lir6_ff4_rsv1/WhirVerifierCore8.sol",
        modulus=0x7F000001,
        tables=(
            TableSpec("POW_TABLE_ROUND0", 1_791_270_792, 24, 6),
            TableSpec("POW_TABLE_ROUND1", 1_760_025_929, 23, 6),
            TableSpec("POW_TABLE_ROUND2", 542_991_299, 22, 6),
            TableSpec("POW_TABLE_FINAL", 1_213_133_211, 21, 6),
        ),
    ),
)


def parse_table(source: str, name: str) -> bytes:
    match = re.search(
        rf'bytes\s+private\s+constant\s+{name}\s*=\s*hex"([0-9a-fA-F]+)"\s*;',
        source,
        flags=re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"missing {name}")
    return bytes.fromhex(match.group(1))


def verify_mapping(source: str, table: TableSpec) -> None:
    decimal = rf"{table.base:,}".replace(",", r"[_]?")
    pattern = rf"base\s*==\s*{decimal}.*?table\s*=\s*{table.name}\s*;"
    if re.search(pattern, source, flags=re.DOTALL) is None:
        raise AssertionError(f"{table.name}: base-to-table mapping is missing")


def verify_table(verifier: VerifierSpec, table: TableSpec, raw: bytes) -> None:
    expected_length = table.windows * 16 * 4
    if len(raw) != expected_length:
        raise AssertionError(
            f"{table.name}: got {len(raw)} bytes, expected {expected_length}"
        )

    if pow(table.base, 1 << table.exponent_bits, verifier.modulus) != 1:
        raise AssertionError(f"{table.name}: generator order is too large")
    if pow(table.base, 1 << (table.exponent_bits - 1), verifier.modulus) == 1:
        raise AssertionError(f"{table.name}: generator order is too small")

    for window in range(table.windows):
        for digit in range(16):
            offset = 4 * (16 * window + digit)
            actual = int.from_bytes(raw[offset : offset + 4], "big")
            expected = pow(
                table.base,
                digit * (16**window),
                verifier.modulus,
            )
            if actual != expected:
                raise AssertionError(
                    f"{table.name}[{window}][{digit}]: got {actual}, expected {expected}"
                )
            if actual >= verifier.modulus:
                raise AssertionError(f"{table.name}[{window}][{digit}] is not canonical")


def main() -> None:
    for verifier in VERIFIERS:
        source = verifier.source.read_text()
        for table in verifier.tables:
            verify_mapping(source, table)
            raw = parse_table(source, table.name)
            verify_table(verifier, table, raw)
            digest = hashlib.sha256(raw).hexdigest()
            print(
                f"{verifier.label} {table.name}: "
                f"{len(raw) // 64} windows, sha256={digest}"
            )


if __name__ == "__main__":
    main()
