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
DEFAULT_MAC_SCHEDULE = "testdata/extfield_mac_gas_schedule.json"
DEFAULT_LIN_PROD_SCHEDULE = "testdata/extfield_lin_prod_gas_schedule.json"
MODULUS = 0x7F000001


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
    bytecode = run(["forge", "inspect", "Ext8PrecompileHarness", "bytecode"]).strip()
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


def array_arg(values: list[str | int]) -> str:
    return "[" + ",".join(hex(v) if isinstance(v, int) else v for v in values) + "]"


def from_base(value: int) -> int:
    return value << 224


def ext8_from_coeffs(
    c0: int, c1: int, c2: int, c3: int, c4: int, c5: int, c6: int, c7: int
) -> int:
    return (
        (c0 << 224)
        | (c1 << 192)
        | (c2 << 160)
        | (c3 << 128)
        | (c4 << 96)
        | (c5 << 64)
        | (c6 << 32)
        | c7
    )


def mac_header(field_id: int, n: int, flags: int) -> bytes:
    return field_id.to_bytes(2, "big") + n.to_bytes(2, "big") + flags.to_bytes(4, "big")


def lin_prod_header(field_id: int, n: int, flags: int) -> bytes:
    return mac_header(field_id, n, flags)


def pack_word(value: str | int) -> bytes:
    raw = int(value, 16) if isinstance(value, str) else value
    return raw.to_bytes(32, "big")


def mac_input(
    accumulator: str | int,
    include_accumulator: bool,
    packed_a: list[str | int],
    packed_b: list[str | int],
    *,
    field_id: int,
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


def lin_prod_input(
    flags: int,
    packed_alpha: list[str | int],
    packed_beta: list[str | int],
    scalars: list[str | int],
    packed_x: list[str | int],
    *,
    field_id: int,
    flags_override: int | None = None,
    n_override: int | None = None,
) -> str:
    n = n_override if n_override is not None else len(packed_x)
    body = bytearray(
        lin_prod_header(
            field_id, n, flags_override if flags_override is not None else flags
        )
    )
    if flags == 0:
        for alpha, beta, x in zip(packed_alpha, packed_beta, packed_x):
            body.extend(pack_word(alpha))
            body.extend(pack_word(beta))
            body.extend(pack_word(x))
    elif flags == 1:
        for beta, x in zip(packed_beta, packed_x):
            body.extend(pack_word(beta))
            body.extend(pack_word(x))
    elif flags == 3:
        for scalar, x in zip(scalars, packed_x):
            raw = int(scalar, 16) if isinstance(scalar, str) else scalar
            body.extend(raw.to_bytes(4, "big"))
            body.extend(pack_word(x))
    else:
        raise ValueError(f"unsupported LIN_PROD flags {flags}")
    return "0x" + body.hex()


def load_mac_protocol(path: Path, field_id: int = 0x0008) -> tuple[int, int]:
    schedule = json.loads(path.read_text())
    for field in schedule["fields"]:
        if int(field["field_id"]) == field_id:
            return int(field["field_id"]), int(field["n_max"])
    raise RuntimeError(f"missing EXTFIELD_MAC field_id={field_id}")


def load_lin_prod_protocol(path: Path, field_id: int = 0x0008) -> tuple[int, int]:
    schedule = json.loads(path.read_text())
    for field in schedule["fields"]:
        if int(field["field_id"]) == field_id:
            return int(field["field_id"]), int(field["n_max"])
    raise RuntimeError(f"missing EXTFIELD_LIN_PROD field_id={field_id}")


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


def run_lin_prod_vectors(
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
            "checkLinProdVectorTx(uint256,uint256[],uint256[],uint256[],uint256[],uint256)(bool)",
            [
                str(vector["flags"]),
                array_arg(vector["packed_alpha"]),
                array_arg(vector["packed_beta"]),
                array_arg(vector["scalars"]),
                array_arg(vector["packed_x"]),
                vector["packed_output"],
            ],
            gas_limit,
        )
        total_gas += gas
        print(
            "lin_prod_vector "
            f"index={idx} field_id={vector['field_id']} flags={vector['flags']} "
            f"n={vector['n']} gas={gas}"
        )
    print(f"lin_prod_vectors={len(vectors)}")
    print(f"lin_prod_vectors_total_gas={total_gas}")


def call_reverts(rpc_url: str, harness: str, signature: str, args: list[str]) -> bool:
    try:
        run(["cast", "call", harness, signature, *args, "--rpc-url", rpc_url])
        return False
    except subprocess.CalledProcessError:
        return True


def run_mac_rejections(
    rpc_url: str,
    private_key: str,
    harness: str,
    field_id: int,
    n_max: int,
    gas_limit: int,
) -> None:
    a = ext8_from_coeffs(1, 2, 3, 4, 5, 6, 7, 8)
    b = ext8_from_coeffs(11, 13, 17, 19, 23, 29, 31, 37)
    ext5_shaped = ext8_from_coeffs(1, 2, 3, 4, 5, 0, 0, 0)
    oversized_limb = a | (MODULUS << 224)
    cases = [
        ("mac_unknown_field", mac_input(0, False, [a], [b], field_id=0x0006)),
        ("mac_oversized_n", "0x" + mac_header(field_id, n_max + 1, 0).hex()),
        ("mac_reserved_flag", "0x" + mac_header(field_id, 0, 2).hex()),
        ("mac_bad_length", "0x" + mac_header(field_id, 1, 0).hex()),
        (
            "mac_extra_accumulator",
            "0x" + mac_header(field_id, 0, 0).hex() + pack_word(a).hex(),
        ),
        ("mac_limb", mac_input(0, False, [oversized_limb], [b], field_id=field_id)),
    ]
    for label, raw_input in cases:
        if not call_reverts(rpc_url, harness, "precompileMacRaw(bytes)", [raw_input]):
            raise RuntimeError(f"{label} accepted invalid EXTFIELD_MAC input")
        print(f"{label}_rejects=true")

    cast_send(
        rpc_url,
        private_key,
        harness,
        "precompileMac(uint256,bool,uint256[],uint256[])(uint256)",
        [hex(0), "false", array_arg([ext5_shaped]), array_arg([b])],
        gas_limit,
    )
    print("mac_ext5_shaped_word_ext8_path_exercised=true")


def run_lin_prod_rejections(
    rpc_url: str,
    harness: str,
    field_id: int,
    n_max: int,
) -> None:
    a = ext8_from_coeffs(1, 2, 3, 4, 5, 6, 7, 8)
    b = ext8_from_coeffs(11, 13, 17, 19, 23, 29, 31, 37)
    x = ext8_from_coeffs(41, 43, 47, 53, 59, 61, 67, 71)
    oversized_limb = x | (MODULUS << 224)
    ext5_shaped = ext8_from_coeffs(1, 2, 3, 4, 5, 0, 0, 0)
    cases = [
        (
            "lin_prod_unknown_field",
            lin_prod_input(3, [], [], [1], [x], field_id=0x0006),
        ),
        ("lin_prod_oversized_n", "0x" + lin_prod_header(field_id, n_max + 1, 3).hex()),
        ("lin_prod_flags2", "0x" + lin_prod_header(field_id, 0, 2).hex()),
        ("lin_prod_reserved_flag", "0x" + lin_prod_header(field_id, 0, 4).hex()),
        ("lin_prod_bad_length", "0x" + lin_prod_header(field_id, 1, 3).hex()),
        (
            "lin_prod_cross_mode_beta",
            "0x"
            + lin_prod_header(field_id, 1, 3).hex()
            + pack_word(b).hex()
            + pack_word(x).hex(),
        ),
        (
            "lin_prod_limb",
            lin_prod_input(3, [], [], [1], [oversized_limb], field_id=field_id),
        ),
        (
            "lin_prod_scalar",
            lin_prod_input(3, [], [], [MODULUS], [x], field_id=field_id),
        ),
    ]
    for label, raw_input in cases:
        if not call_reverts(
            rpc_url, harness, "precompileLinProdRaw(bytes)", [raw_input]
        ):
            raise RuntimeError(f"{label} accepted invalid EXTFIELD_LIN_PROD input")
        print(f"{label}_rejects=true")

    run(
        [
            "cast",
            "call",
            harness,
            "precompileLinProdRaw(bytes)",
            lin_prod_input(3, [], [], [1], [ext5_shaped], field_id=field_id),
            "--rpc-url",
            rpc_url,
        ]
    )
    print("lin_prod_ext5_shaped_word_ext8_path_exercised=true")


def run_mac_benchmarks(
    rpc_url: str,
    private_key: str,
    harness: str,
    gas_limit: int,
    n_max: int,
) -> None:
    accumulator = ext8_from_coeffs(1, 2, 3, 4, 5, 6, 7, 8)
    for n in (1, 16, 64, n_max):
        packed_a = [
            ext8_from_coeffs(
                ((i * 3 + 1) % (MODULUS - 1)) + 1,
                ((i * 5 + 2) % (MODULUS - 1)) + 1,
                ((i * 7 + 3) % (MODULUS - 1)) + 1,
                ((i * 11 + 4) % (MODULUS - 1)) + 1,
                ((i * 13 + 5) % (MODULUS - 1)) + 1,
                ((i * 17 + 6) % (MODULUS - 1)) + 1,
                ((i * 19 + 7) % (MODULUS - 1)) + 1,
                ((i * 23 + 8) % (MODULUS - 1)) + 1,
            )
            for i in range(n)
        ]
        packed_b = [
            ext8_from_coeffs(
                ((i * 29 + 9) % (MODULUS - 1)) + 1,
                ((i * 31 + 10) % (MODULUS - 1)) + 1,
                ((i * 37 + 11) % (MODULUS - 1)) + 1,
                ((i * 41 + 12) % (MODULUS - 1)) + 1,
                ((i * 43 + 13) % (MODULUS - 1)) + 1,
                ((i * 47 + 14) % (MODULUS - 1)) + 1,
                ((i * 53 + 15) % (MODULUS - 1)) + 1,
                ((i * 59 + 16) % (MODULUS - 1)) + 1,
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


def run_lin_prod_benchmarks(
    rpc_url: str,
    private_key: str,
    harness: str,
    gas_limit: int,
    n_max: int,
) -> None:
    for flags in (0, 1, 3):
        for n in (10, 14, 18, 64, n_max):
            packed_alpha = [
                ext8_from_coeffs(i + 1, i + 2, i + 3, i + 4, i + 5, i + 6, i + 7, i + 8)
                for i in range(n)
            ]
            packed_beta = [
                ext8_from_coeffs(
                    i + 11, i + 13, i + 17, i + 19, i + 23, i + 29, i + 31, i + 37
                )
                for i in range(n)
            ]
            scalars = [((i * 17 + 1) % (MODULUS - 1)) + 1 for i in range(n)]
            packed_x = [
                ext8_from_coeffs(
                    i + 41, i + 43, i + 47, i + 53, i + 59, i + 61, i + 67, i + 71
                )
                for i in range(n)
            ]
            noop_gas = cast_send(
                rpc_url,
                private_key,
                harness,
                "benchmarkNoopLinProd(uint256,uint256[],uint256[],uint256[],uint256[])",
                [
                    str(flags),
                    array_arg(packed_alpha),
                    array_arg(packed_beta),
                    array_arg(scalars),
                    array_arg(packed_x),
                ],
                gas_limit,
            )
            real_gas = cast_send(
                rpc_url,
                private_key,
                harness,
                "benchmarkLinProd(uint256,uint256[],uint256[],uint256[],uint256[])",
                [
                    str(flags),
                    array_arg(packed_alpha),
                    array_arg(packed_beta),
                    array_arg(scalars),
                    array_arg(packed_x),
                ],
                gas_limit,
            )
            print(f"noop_lin_prod_flags{flags}_n{n}_gas={noop_gas}")
            print(f"lin_prod_flags{flags}_n{n}_gas={real_gas}")


def run_benchmarks(
    rpc_url: str, private_key: str, harness: str, gas_limit: int
) -> None:
    full_point = [from_base((i % 17) + 1) for i in range(22)]
    sel_vars = [((i + 1) * 7 % (MODULUS - 1)) + 1 for i in range(24)]
    challenge = from_base(7)
    ood_point = from_base(5)
    eq_eval = from_base(11)

    # Avoid charging the first measured call for the zero-to-nonzero SSTORE on lastResult.
    cast_send(
        rpc_url,
        private_key,
        harness,
        "benchmarkNoopSquareClean(uint256)",
        [hex(ood_point)],
        gas_limit,
    )

    calls = [
        (
            "noop_mul_clean",
            "benchmarkNoopMulClean(uint256,uint256)",
            [ood_point, eq_eval],
        ),
        ("noop_square_clean", "benchmarkNoopSquareClean(uint256)", [ood_point]),
        (
            "eq22_software",
            "benchmarkEqExpanded22Software(uint256,uint256[])",
            [ood_point, full_point],
        ),
        (
            "eq22_noop",
            "benchmarkEqExpanded22Noop(uint256,uint256[])",
            [ood_point, full_point],
        ),
        (
            "eq22_precompile",
            "benchmarkEqExpanded22Precompile(uint256,uint256[])",
            [ood_point, full_point],
        ),
        (
            "eq18_software",
            "benchmarkEqExpanded18Software(uint256,uint256[])",
            [ood_point, full_point],
        ),
        (
            "eq18_noop",
            "benchmarkEqExpanded18Noop(uint256,uint256[])",
            [ood_point, full_point],
        ),
        (
            "eq18_precompile",
            "benchmarkEqExpanded18Precompile(uint256,uint256[])",
            [ood_point, full_point],
        ),
        (
            "eq14_software",
            "benchmarkEqExpanded14Software(uint256,uint256[])",
            [ood_point, full_point],
        ),
        (
            "eq14_noop",
            "benchmarkEqExpanded14Noop(uint256,uint256[])",
            [ood_point, full_point],
        ),
        (
            "eq14_precompile",
            "benchmarkEqExpanded14Precompile(uint256,uint256[])",
            [ood_point, full_point],
        ),
        (
            "eq10_software",
            "benchmarkEqExpanded10Software(uint256,uint256[])",
            [ood_point, full_point],
        ),
        (
            "eq10_noop",
            "benchmarkEqExpanded10Noop(uint256,uint256[])",
            [ood_point, full_point],
        ),
        (
            "eq10_precompile",
            "benchmarkEqExpanded10Precompile(uint256,uint256[])",
            [ood_point, full_point],
        ),
        (
            "round0_select_only_software",
            "benchmarkRound0SelectOnlySoftware(uint256,uint256,uint256[],uint256[])",
            [challenge, eq_eval, sel_vars, full_point],
        ),
        (
            "round0_select_only_noop",
            "benchmarkRound0SelectOnlyNoop(uint256,uint256,uint256[],uint256[])",
            [challenge, eq_eval, sel_vars, full_point],
        ),
        (
            "round0_select_only_precompile",
            "benchmarkRound0SelectOnlyPrecompile(uint256,uint256,uint256[],uint256[])",
            [challenge, eq_eval, sel_vars, full_point],
        ),
        (
            "round0_eq_select_software",
            "benchmarkRound0EqSelectSoftware(uint256,uint256,uint256[],uint256[])",
            [challenge, ood_point, sel_vars, full_point],
        ),
        (
            "round0_eq_select_noop",
            "benchmarkRound0EqSelectNoop(uint256,uint256,uint256[],uint256[])",
            [challenge, ood_point, sel_vars, full_point],
        ),
        (
            "round0_eq_select_precompile",
            "benchmarkRound0EqSelectPrecompile(uint256,uint256,uint256[],uint256[])",
            [challenge, ood_point, sel_vars, full_point],
        ),
        (
            "round1_select_only_software",
            "benchmarkRound1SelectOnlySoftware(uint256,uint256,uint256[],uint256[])",
            [challenge, eq_eval, sel_vars, full_point],
        ),
        (
            "round1_select_only_noop",
            "benchmarkRound1SelectOnlyNoop(uint256,uint256,uint256[],uint256[])",
            [challenge, eq_eval, sel_vars, full_point],
        ),
        (
            "round1_select_only_precompile",
            "benchmarkRound1SelectOnlyPrecompile(uint256,uint256,uint256[],uint256[])",
            [challenge, eq_eval, sel_vars, full_point],
        ),
        (
            "round1_eq_select_software",
            "benchmarkRound1EqSelectSoftware(uint256,uint256,uint256[],uint256[])",
            [challenge, ood_point, sel_vars, full_point],
        ),
        (
            "round1_eq_select_noop",
            "benchmarkRound1EqSelectNoop(uint256,uint256,uint256[],uint256[])",
            [challenge, ood_point, sel_vars, full_point],
        ),
        (
            "round1_eq_select_precompile",
            "benchmarkRound1EqSelectPrecompile(uint256,uint256,uint256[],uint256[])",
            [challenge, ood_point, sel_vars, full_point],
        ),
        (
            "round2_select_only_software",
            "benchmarkRound2SelectOnlySoftware(uint256,uint256,uint256[],uint256[])",
            [challenge, eq_eval, sel_vars, full_point],
        ),
        (
            "round2_select_only_noop",
            "benchmarkRound2SelectOnlyNoop(uint256,uint256,uint256[],uint256[])",
            [challenge, eq_eval, sel_vars, full_point],
        ),
        (
            "round2_select_only_precompile",
            "benchmarkRound2SelectOnlyPrecompile(uint256,uint256,uint256[],uint256[])",
            [challenge, eq_eval, sel_vars, full_point],
        ),
        (
            "round2_eq_select_software",
            "benchmarkRound2EqSelectSoftware(uint256,uint256,uint256[],uint256[])",
            [challenge, ood_point, sel_vars, full_point],
        ),
        (
            "round2_eq_select_noop",
            "benchmarkRound2EqSelectNoop(uint256,uint256,uint256[],uint256[])",
            [challenge, ood_point, sel_vars, full_point],
        ),
        (
            "round2_eq_select_precompile",
            "benchmarkRound2EqSelectPrecompile(uint256,uint256,uint256[],uint256[])",
            [challenge, ood_point, sel_vars, full_point],
        ),
    ]

    gas_by_label: dict[str, int] = {}
    for label, signature, raw_args in calls:
        encoded_args = [
            array_arg(arg) if isinstance(arg, list) else hex(arg) for arg in raw_args
        ]
        gas = cast_send(
            rpc_url, private_key, harness, signature, encoded_args, gas_limit
        )
        gas_by_label[label] = gas
        print(f"{label}: {gas}")

    print("---")
    eq_delta = sum(
        gas_by_label[f"eq{arity}_software"] - gas_by_label[f"eq{arity}_precompile"]
        for arity in (22, 18, 14, 10)
    )
    select_delta = sum(
        gas_by_label[f"round{round_idx}_select_only_software"]
        - gas_by_label[f"round{round_idx}_select_only_precompile"]
        for round_idx in (0, 1, 2)
    )
    combined_delta = sum(
        gas_by_label[f"round{round_idx}_eq_select_software"]
        - gas_by_label[f"round{round_idx}_eq_select_precompile"]
        for round_idx in (0, 1, 2)
    )
    print(f"eq_only_delta: {eq_delta}")
    print(f"select_only_delta: {select_delta}")
    print(f"combined_delta: {combined_delta}")
    print(f"clean_transport_mul_tx_gas: {gas_by_label['noop_mul_clean']}")
    print(f"clean_transport_square_tx_gas: {gas_by_label['noop_square_clean']}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rpc-url", default=DEFAULT_RPC_URL)
    parser.add_argument("--private-key", default=DEFAULT_PRIVATE_KEY)
    parser.add_argument("--sender", default=DEFAULT_SENDER)
    parser.add_argument("--harness")
    parser.add_argument(
        "--vectors", type=Path, default=Path("testdata/ext8_precompile_vectors.json")
    )
    parser.add_argument(
        "--mac-vectors",
        type=Path,
        default=Path("testdata/extfield_mac_ext8_vectors.json"),
    )
    parser.add_argument("--mac-schedule", type=Path, default=Path(DEFAULT_MAC_SCHEDULE))
    parser.add_argument(
        "--lin-prod-vectors",
        type=Path,
        default=Path("testdata/extfield_lin_prod_ext8_vectors.json"),
    )
    parser.add_argument(
        "--lin-prod-schedule", type=Path, default=Path(DEFAULT_LIN_PROD_SCHEDULE)
    )
    parser.add_argument("--chunk-size", type=int, default=250)
    parser.add_argument("--gas-limit", type=int, default=30_000_000)
    parser.add_argument("--skip-arithmetic", action="store_true")
    parser.add_argument("--skip-mac-vectors", action="store_true")
    parser.add_argument("--skip-lin-prod-vectors", action="store_true")
    parser.add_argument("--skip-benchmarks", action="store_true")
    args = parser.parse_args()
    mac_field_id, mac_n_max = load_mac_protocol(args.mac_schedule)
    lin_prod_field_id, lin_prod_n_max = load_lin_prod_protocol(args.lin_prod_schedule)

    harness = args.harness or deploy_harness(args.rpc_url, args.sender, args.gas_limit)
    print(f"harness={harness}")

    if not args.skip_arithmetic:
        run_arithmetic(
            args.rpc_url,
            args.sender,
            harness,
            args.vectors,
            args.chunk_size,
            args.gas_limit,
        )
    if not args.skip_mac_vectors:
        run_mac_vectors(
            args.rpc_url,
            args.sender,
            harness,
            args.mac_vectors,
            args.gas_limit,
        )
    if not args.skip_lin_prod_vectors:
        run_lin_prod_vectors(
            args.rpc_url,
            args.sender,
            harness,
            args.lin_prod_vectors,
            args.gas_limit,
        )
    if not args.skip_benchmarks:
        run_mac_rejections(
            args.rpc_url,
            args.sender,
            harness,
            mac_field_id,
            mac_n_max,
            args.gas_limit,
        )
        run_mac_benchmarks(
            args.rpc_url, args.sender, harness, args.gas_limit, mac_n_max
        )
        run_lin_prod_rejections(
            args.rpc_url, harness, lin_prod_field_id, lin_prod_n_max
        )
        run_lin_prod_benchmarks(
            args.rpc_url, args.sender, harness, args.gas_limit, lin_prod_n_max
        )
        run_benchmarks(args.rpc_url, args.sender, harness, args.gas_limit)


if __name__ == "__main__":
    main()
