#!/usr/bin/env python3
import argparse
import json
import subprocess
import time
import urllib.request
from pathlib import Path

DEFAULT_RPC_URL = "http://127.0.0.1:18547"
DEFAULT_PRIVATE_KEY = (
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
)
DEFAULT_SENDER = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
MODULUS = 0x7F000001
EXTFIELD_MAC_FIELD_ID_EXT5 = 0x0005


def run(args: list[str]) -> str:
    completed = subprocess.run(args, check=True, text=True, capture_output=True)
    return completed.stdout


def rpc(rpc_url: str, method: str, params: list) -> object:
    payload = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    ).encode()
    req = urllib.request.Request(
        rpc_url, data=payload, headers={"content-type": "application/json"}
    )
    with urllib.request.urlopen(req) as resp:
        decoded = json.loads(resp.read())
    if "error" in decoded:
        raise RuntimeError(f"rpc {method} failed: {decoded['error']}")
    return decoded["result"]


def wait_receipt(rpc_url: str, tx_hash: str) -> dict:
    for _ in range(120):
        receipt = rpc(rpc_url, "eth_getTransactionReceipt", [tx_hash])
        if receipt is not None:
            return receipt
        time.sleep(0.25)
    raise RuntimeError(f"timed out waiting for receipt {tx_hash}")


def deploy_harness(rpc_url: str, sender: str, gas_limit: int) -> str:
    bytecode = run(["forge", "inspect", "Ext5PrecompileHarness", "bytecode"]).strip()
    tx_hash = rpc(
        rpc_url,
        "eth_sendTransaction",
        [{"from": sender, "data": bytecode, "gas": hex(gas_limit)}],
    )
    receipt = wait_receipt(rpc_url, tx_hash)
    if receipt.get("status") != "0x1":
        raise RuntimeError(f"harness deployment reverted: {receipt}")
    return receipt["contractAddress"]


def cast_send(
    rpc_url: str,
    sender: str,
    harness: str,
    signature: str,
    args: list[str],
    gas_limit: int,
) -> int:
    calldata = run(["cast", "calldata", signature, *args]).strip()
    tx_hash = rpc(
        rpc_url,
        "eth_sendTransaction",
        [{"from": sender, "to": harness, "data": calldata, "gas": hex(gas_limit)}],
    )
    receipt = wait_receipt(rpc_url, tx_hash)
    if receipt.get("status") != "0x1":
        raise RuntimeError(f"transaction reverted for {signature}: {receipt}")
    return int(receipt["gasUsed"], 16)


def cast_call_reverts(
    rpc_url: str,
    harness: str,
    signature: str,
    args: list[str],
) -> bool:
    calldata = run(["cast", "calldata", signature, *args]).strip()
    try:
        rpc(
            rpc_url,
            "eth_call",
            [{"to": harness, "data": calldata, "gas": hex(1_000_000)}, "latest"],
        )
        return False
    except RuntimeError:
        return True


def array_arg(values: list[str | int]) -> str:
    return "[" + ",".join(hex(v) if isinstance(v, int) else v for v in values) + "]"


def ext5_from_coeffs(c0: int, c1: int, c2: int, c3: int, c4: int) -> int:
    return (c0 << 224) | (c1 << 192) | (c2 << 160) | (c3 << 128) | (c4 << 96)


def mac_header(field_id: int, n: int, flags: int) -> bytes:
    return field_id.to_bytes(2, "big") + n.to_bytes(2, "big") + flags.to_bytes(4, "big")


def pack_word(value: str | int) -> bytes:
    raw = int(value, 16) if isinstance(value, str) else value
    return raw.to_bytes(32, "big")


def mac_input(
    accumulator: str | int,
    include_accumulator: bool,
    packed_a: list[str | int],
    packed_b: list[str | int],
    *,
    field_id: int = EXTFIELD_MAC_FIELD_ID_EXT5,
    flags_override: int | None = None,
    n_override: int | None = None,
) -> str:
    if len(packed_a) != len(packed_b):
        raise ValueError("MAC input pair length mismatch")
    flags = (
        flags_override
        if flags_override is not None
        else (1 if include_accumulator else 0)
    )
    n = n_override if n_override is not None else len(packed_a)
    body = bytearray(mac_header(field_id, n, flags))
    if include_accumulator:
        body.extend(pack_word(accumulator))
    for a, b in zip(packed_a, packed_b):
        body.extend(pack_word(a))
        body.extend(pack_word(b))
    return "0x" + body.hex()


def run_arithmetic(
    rpc_url: str,
    private_key: str,
    harness: str,
    vectors_path: Path,
    chunk_size: int,
    gas_limit: int,
) -> None:
    vectors = json.loads(vectors_path.read_text())["vectors"]
    total_gas = 0
    for start in range(0, len(vectors), chunk_size):
        chunk = vectors[start : start + chunk_size]
        gas = cast_send(
            rpc_url,
            private_key,
            harness,
            "checkArithmeticVectorsTx(uint256[],uint256[],uint256[],uint256[])(bool)",
            [
                array_arg([v["packed_a"] for v in chunk]),
                array_arg([v["packed_b"] for v in chunk]),
                array_arg([v["packed_mul"] for v in chunk]),
                array_arg([v["packed_square_a"] for v in chunk]),
            ],
            gas_limit,
        )
        total_gas += gas
        print(f"arithmetic_chunk start={start} count={len(chunk)} gas={gas}")
    print(f"arithmetic_vectors={len(vectors)}")
    print(f"arithmetic_total_gas={total_gas}")


def run_mac_vectors(
    rpc_url: str,
    private_key: str,
    harness: str,
    vectors_path: Path,
    gas_limit: int,
) -> None:
    vectors = json.loads(vectors_path.read_text())["vectors"]
    total_gas = 0
    for idx, vector in enumerate(vectors):
        gas = cast_send(
            rpc_url,
            private_key,
            harness,
            "checkMacVectorTx(uint256,bool,uint256[],uint256[],uint256)(bool)",
            [
                vector["packed_accumulator"],
                "true" if vector["include_accumulator"] else "false",
                array_arg(vector["packed_a"]),
                array_arg(vector["packed_b"]),
                vector["packed_output"],
            ],
            gas_limit,
        )
        total_gas += gas
        print(
            "mac_vector "
            f"index={idx} n={vector['n']} "
            f"accumulator={str(vector['include_accumulator']).lower()} gas={gas}"
        )
    print(f"mac_vectors={len(vectors)}")
    print(f"mac_vectors_total_gas={total_gas}")


def run_mac_rejections(rpc_url: str, harness: str) -> None:
    a = ext5_from_coeffs(1, 2, 3, 4, 5)
    b = ext5_from_coeffs(7, 11, 13, 17, 19)
    low_bits_dirty = a | 1
    oversized_limb = a | (MODULUS << 224)
    cases = [
        ("mac_unknown_field", mac_input(0, False, [a], [b], field_id=0x0006)),
        (
            "mac_oversized_n",
            "0x" + mac_header(EXTFIELD_MAC_FIELD_ID_EXT5, 1025, 0).hex(),
        ),
        (
            "mac_reserved_flag",
            "0x" + mac_header(EXTFIELD_MAC_FIELD_ID_EXT5, 0, 2).hex(),
        ),
        ("mac_bad_length", "0x" + mac_header(EXTFIELD_MAC_FIELD_ID_EXT5, 1, 0).hex()),
        (
            "mac_extra_accumulator",
            "0x"
            + mac_header(EXTFIELD_MAC_FIELD_ID_EXT5, 0, 0).hex()
            + pack_word(a).hex(),
        ),
        ("mac_low96", mac_input(0, False, [low_bits_dirty], [b])),
        ("mac_limb", mac_input(0, False, [oversized_limb], [b])),
    ]
    for label, raw_input in cases:
        if not cast_call_reverts(
            rpc_url, harness, "precompileMacRaw(bytes)", [raw_input]
        ):
            raise RuntimeError(f"{label} accepted invalid EXTFIELD_MAC input")
        print(f"{label}_rejects=true")


def run_mac_benchmarks(
    rpc_url: str,
    private_key: str,
    harness: str,
    gas_limit: int,
) -> None:
    accumulator = ext5_from_coeffs(1, 2, 3, 4, 5)
    for n in (1, 16, 64, 1024):
        packed_a = [
            ext5_from_coeffs(
                ((i * 3 + 1) % (MODULUS - 1)) + 1,
                ((i * 5 + 2) % (MODULUS - 1)) + 1,
                ((i * 7 + 3) % (MODULUS - 1)) + 1,
                ((i * 11 + 4) % (MODULUS - 1)) + 1,
                ((i * 13 + 5) % (MODULUS - 1)) + 1,
            )
            for i in range(n)
        ]
        packed_b = [
            ext5_from_coeffs(
                ((i * 17 + 6) % (MODULUS - 1)) + 1,
                ((i * 19 + 7) % (MODULUS - 1)) + 1,
                ((i * 23 + 8) % (MODULUS - 1)) + 1,
                ((i * 29 + 9) % (MODULUS - 1)) + 1,
                ((i * 31 + 10) % (MODULUS - 1)) + 1,
            )
            for i in range(n)
        ]
        noop_gas = cast_send(
            rpc_url,
            private_key,
            harness,
            "benchmarkNoopMac(uint256,bool,uint256[],uint256[])",
            [hex(accumulator), "true", array_arg(packed_a), array_arg(packed_b)],
            gas_limit,
        )
        real_gas = cast_send(
            rpc_url,
            private_key,
            harness,
            "benchmarkMac(uint256,bool,uint256[],uint256[])",
            [hex(accumulator), "true", array_arg(packed_a), array_arg(packed_b)],
            gas_limit,
        )
        print(f"noop_mac_n{n}_gas={noop_gas}")
        print(f"mac_n{n}_gas={real_gas}")


def run_benchmarks(
    rpc_url: str, private_key: str, harness: str, batch_size: int, gas_limit: int
) -> None:
    a = ext5_from_coeffs(1, 2, 3, 4, 5)
    b = ext5_from_coeffs(7, 11, 13, 17, 19)
    packed_a = [
        ext5_from_coeffs(
            ((i * 3 + 1) % (MODULUS - 1)) + 1,
            ((i * 5 + 2) % (MODULUS - 1)) + 1,
            ((i * 7 + 3) % (MODULUS - 1)) + 1,
            ((i * 11 + 4) % (MODULUS - 1)) + 1,
            ((i * 13 + 5) % (MODULUS - 1)) + 1,
        )
        for i in range(batch_size)
    ]
    packed_b = [
        ext5_from_coeffs(
            ((i * 17 + 6) % (MODULUS - 1)) + 1,
            ((i * 19 + 7) % (MODULUS - 1)) + 1,
            ((i * 23 + 8) % (MODULUS - 1)) + 1,
            ((i * 29 + 9) % (MODULUS - 1)) + 1,
            ((i * 31 + 10) % (MODULUS - 1)) + 1,
        )
        for i in range(batch_size)
    ]

    # Avoid charging the first measured call for zero-to-nonzero SSTORE on lastResult.
    cast_send(
        rpc_url,
        private_key,
        harness,
        "benchmarkNoopSquareClean(uint256)",
        [hex(a)],
        gas_limit,
    )
    low_bits_dirty = a | 1
    oversized_limb = a | (MODULUS << 224)
    rejection_cases = [
        ("mul_low96", "precompileMul(uint256,uint256)", [hex(low_bits_dirty), hex(a)]),
        ("mul_limb", "precompileMul(uint256,uint256)", [hex(oversized_limb), hex(a)]),
        ("square_low96", "precompileSquare(uint256)", [hex(low_bits_dirty)]),
        ("square_limb", "precompileSquare(uint256)", [hex(oversized_limb)]),
    ]
    for label, sig, args in rejection_cases:
        if not cast_call_reverts(rpc_url, harness, sig, args):
            raise RuntimeError(f"{label} accepted non-canonical input")
    print("rejects_noncanonical=true")

    calls = [
        ("noop_mul_clean", "benchmarkNoopMulClean(uint256,uint256)", [hex(a), hex(b)]),
        ("mul_clean", "benchmarkMulClean(uint256,uint256)", [hex(a), hex(b)]),
        ("noop_square_clean", "benchmarkNoopSquareClean(uint256)", [hex(a)]),
        ("square_clean", "benchmarkSquareClean(uint256)", [hex(a)]),
        (
            "noop_mul_batch",
            "benchmarkNoopMulBatch(uint256[],uint256[])",
            [array_arg(packed_a), array_arg(packed_b)],
        ),
        (
            "mul_batch",
            "benchmarkMulBatch(uint256[],uint256[])",
            [array_arg(packed_a), array_arg(packed_b)],
        ),
        (
            "noop_square_batch",
            "benchmarkNoopSquareBatch(uint256[])",
            [array_arg(packed_a)],
        ),
        ("square_batch", "benchmarkSquareBatch(uint256[])", [array_arg(packed_a)]),
    ]

    for label, sig, args in calls:
        gas = cast_send(rpc_url, private_key, harness, sig, args, gas_limit)
        print(f"{label}_gas={gas}")

    run_mac_rejections(rpc_url, harness)
    run_mac_benchmarks(rpc_url, private_key, harness, gas_limit)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rpc-url", default=DEFAULT_RPC_URL)
    parser.add_argument("--private-key", default=DEFAULT_PRIVATE_KEY)
    parser.add_argument("--sender", default=DEFAULT_SENDER)
    parser.add_argument(
        "--vectors",
        default="testdata/ext5_precompile_vectors.json",
        help="JSON generated by the ext5 precompile runner",
    )
    parser.add_argument(
        "--mac-vectors",
        default="testdata/extfield_mac_vectors.json",
        help="JSON generated by export-extfield-mac-vectors",
    )
    parser.add_argument("--chunk-size", type=int, default=32)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--gas-limit", type=int, default=50_000_000)
    parser.add_argument("--skip-arithmetic", action="store_true")
    parser.add_argument("--skip-mac-vectors", action="store_true")
    parser.add_argument("--skip-benchmarks", action="store_true")
    args = parser.parse_args()

    harness = deploy_harness(args.rpc_url, args.sender, args.gas_limit)
    print(f"harness={harness}")

    if not args.skip_arithmetic:
        run_arithmetic(
            args.rpc_url,
            args.sender,
            harness,
            Path(args.vectors),
            args.chunk_size,
            args.gas_limit,
        )
    if not args.skip_mac_vectors:
        run_mac_vectors(
            args.rpc_url,
            args.sender,
            harness,
            Path(args.mac_vectors),
            args.gas_limit,
        )
    if not args.skip_benchmarks:
        run_benchmarks(
            args.rpc_url, args.sender, harness, args.batch_size, args.gas_limit
        )


if __name__ == "__main__":
    main()
