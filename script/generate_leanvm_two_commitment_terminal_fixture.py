#!/usr/bin/env python3
"""Generate the Solidity fixture for the version-one terminal C1 proof."""

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from leanvm_terminal_fixture_codec import (
    PostcardProof,
    config_lines,
    dynamic_bytes,
    keccak256,
    limbs_digest,
    packed_extension,
    tuple_encoding,
    word,
)


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO.parent / "leanVM/crates/lean_prover/python-verifier"))
from primitives import Fp, POSEIDON16, poseidon16_compress  # noqa: E402

MODULUS = 2_130_706_433
ONE_PACKED = 1 << 224
SCHEMA = "leanvm-terminal-two-commitment-fixture-v1"
MODE = "terminal-c1-two-commitment-whir-v1"
HASH_BACKEND = "leanvm-keccak240-v1"
MODE_TAG = 0x32570001
STATEMENT_TAG = 0x32574F31
CAP_SCOPE = (
    "static protocol shape, statement structure, selectors, public memory offsets, "
    "exact point prefixes, and fixed bytecode"
)
PROGRAMS = ("spark", "lift", "root")
PROGRAM_DIMENSIONS = [22, 21, 21]
STATEMENT_MEMORY_OFFSETS = [128, 8]
STATEMENT_PREFIXES = [
    [[0, 0, 0, 0, 0]],
    [[1, 0, 0, 0, 0], [0, 0, 0, 0, 0]],
]


def expected_opening_batches(whir, first_folding_factor, subsequent_folding_factor):
    """Derive the batch layout implied by the exported WHIR round structure."""
    rounds = whir["rounds"]
    roles = ["primary_initial", "fixed_program_initial"]
    roles += [f"continuation_{i}" for i in range(1, len(rounds))]
    roles.append("continuation_final")
    initial = rounds[0]
    assert initial["folding_factor"] == first_folding_factor
    queries = [initial["num_queries"], initial["num_queries"]]
    widths = [1 << first_folding_factor] * 2
    heights = [initial["domain_size"].bit_length() - 1 - first_folding_factor] * 2
    for round_config in rounds[1:] + [whir["final_round"]]:
        assert round_config["folding_factor"] == subsequent_folding_factor
        queries.append(round_config["num_queries"])
        widths.append(5 << subsequent_folding_factor)
        heights.append(
            round_config["domain_size"].bit_length() - 1 - subsequent_folding_factor
        )
    return roles, queries, widths, heights


SNARK_DOMAIN_SEPARATOR = [
    130704175,
    1303721200,
    493664240,
    1035493700,
    2063844858,
    1410214009,
    1938905908,
    1696767928,
]


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def padded(count):
    return (count + 7) & ~7


def array_literal(values):
    assert values
    return "[uint256(" + str(values[0]) + ")," + ",".join(map(str, values[1:])) + "]"


def flatten_claim(claim):
    fields = [coefficient for coordinate in claim["point"] for coefficient in coordinate]
    fields.extend(claim["value"])
    fields.extend([0] * (-len(fields) % 8))
    return fields


def expected_statement_observation(claims, variables):
    encoded = [STATEMENT_TAG, 2, 24 + 10 * variables, 0]
    encoded.extend([variables, variables, 1, 0])
    encoded.extend([0] * 5)
    encoded.extend(coefficient for coordinate in claims["spark"]["point"] for coefficient in coordinate)
    encoded.append(0)
    encoded.extend(claims["spark"]["value"])
    encoded.extend([variables, variables, 1, 0])
    encoded.extend([1, 0, 0, 0, 0])
    encoded.extend([0] * 5)
    encoded.extend(coefficient for coordinate in claims["lift"]["point"] for coefficient in coordinate)
    encoded.append(0)
    encoded.extend(claims["lift"]["value"])
    return encoded


def point_prefix_length(binding):
    length = len(binding["point_prefix"])
    if "point_prefix_len" in binding:
        assert binding["point_prefix_len"] == length
    return length


def expected_static_descriptor(c1):
    execution_prefix = c1["execution_bytecode_point_prefix"]
    bindings = c1["secondary_statement_public_memory_bindings"]
    fields = [
        c1["protocol_mode_tag"],
        c1["two_commitment_batching_pow_bits"],
        c1["secondary"]["num_variables"],
        c1["secondary"]["actual_data_len"],
        len(bindings),
        len(execution_prefix),
        0,
        len(bindings),
    ]
    for value in execution_prefix:
        fields.extend([value, 0, 0, 0, 0])
    for dimension, binding in zip(PROGRAM_DIMENSIONS[:2], bindings):
        prefix_length = point_prefix_length(binding)
        fields.extend(
            [
                c1["secondary"]["num_variables"],
                dimension + prefix_length,
                1,
                0,
                binding["public_memory_offset"],
                prefix_length,
            ]
        )
        for coordinate in binding["point_prefix"]:
            fields.extend(coordinate)
        fields.append(0)
    fields[6] = len(fields)
    unpadded_length = len(fields)
    fields.extend([0] * (-len(fields) % 8))
    return unpadded_length, fields


def poseidon_hash_slice(values):
    assert values and len(values) % 8 == 0
    capacity = [Fp(len(values))] + [Fp(0)] * 7
    state = capacity + [Fp(0)] * 8
    for start in range(0, len(values), 8):
        state = POSEIDON16.permute(capacity + [Fp(value) for value in values[start:start + 8]])
        capacity = state[:8]
    return state[8:]


def recompute_c1_capacity(root_program_hash, profile, descriptor):
    base = poseidon16_compress(
        [Fp(value) for value in root_program_hash],
        [Fp(value) for value in SNARK_DOMAIN_SEPARATOR],
    )
    profile_fields = [
        0x57500001,
        profile["security_bits"],
        profile["grinding_bits"],
        profile["first_folding_factor"],
        profile["subsequent_folding_factor"],
        profile["rs_domain_initial_reduction_factor"],
        profile["max_num_variables_to_send_coeffs"],
        profile["log_inv_rate"],
    ]
    profile_capacity = poseidon16_compress(base, [Fp(value) for value in profile_fields])
    descriptor_hash = poseidon_hash_slice(descriptor)
    return [value.value for value in poseidon16_compress(profile_capacity, descriptor_hash)]


def validate_extension(value, label):
    assert isinstance(value, list) and len(value) == 5, label
    assert all(type(x) is int and 0 <= x < MODULUS for x in value), label


def validate_digest(value, label):
    assert isinstance(value, list) and len(value) == 8, label
    assert all(type(x) is int and 0 <= x < 1 << 30 for x in value), label


def validate_base_array(value, length, label):
    assert isinstance(value, list) and len(value) == length, label
    assert all(type(x) is int and 0 <= x < MODULUS for x in value), label


def request_column_counts():
    """Extension-value counts for the selected LogUp column requests."""
    counts = [[], [], []]
    seen = [set(), set(), set()]
    for table in range(3):
        bus_count = 4 if table == 1 else 5
        for bus in range(1, bus_count):
            if table == 0 and bus == 1:
                base = list(range(8, 20)) + [0]
                terms = 1
            elif table == 0:
                base = [bus, bus + 3]
                terms = 1
            elif table == 1:
                base = [[6, 14], [7, 19], [13, 24]][bus - 1]
                terms = 5
            else:
                base = [[7, 10], [8, 14], [1, 18], [2, 94]][bus - 1]
                terms = [4, 4, 8, 16][bus - 1]
            for term in range(terms):
                indices = list(base)
                for i in range(1, len(indices)):
                    indices[i] += term
                old_seen = seen[table].copy()
                count = sum(index not in old_seen for index in indices)
                counts[table].append(count)
                seen[table].update(indices)
    return counts


def transcript_layout(fixture):
    """Derive the selected verifier's raw transcript boundaries in base words."""
    raw = fixture["raw_transcript"]
    dimensions = raw[:5]
    assert dimensions == [6, 19, 17, 15, 13], "selected execution dimensions"
    _, memory_log, execution_log, extension_log, poseidon_log = dimensions
    table_heights = [execution_log, extension_log, poseidon_log]
    maximum = max(table_heights)
    bytecode_log = fixture["bytecodes"][2]["log_instructions"]
    active = (1 << memory_log) + (1 << max(bytecode_log, maximum))
    for buses, height in zip([5, 16, 33], table_heights):
        active += buses << height
    gkr_variables = (active - 1).bit_length()
    assert gkr_variables == 22, "selected GKR dimension"

    offset = 0

    def consume(fields):
        nonlocal offset
        start = offset
        offset += padded(fields)
        assert all(value == 0 for value in raw[start + fields:offset]), (
            "nonzero raw transcript padding",
            start,
            fields,
        )
        return start

    consume(5)  # dimensions
    primary_root = consume(8)
    secondary_root = consume(8)
    consume(5 * 32)
    consume(5 * 32)
    for layer in range(5, gkr_variables):
        for _ in range(layer):
            consume(5 * 4)
        consume(5 * 4)
    consume(5)  # memory accumulator
    consume(5)  # memory value
    consume(5)  # bytecode accumulator
    for table_counts in request_column_counts():
        consume(5)  # table numerator
        consume(5)  # table denominator
        for count in table_counts:
            consume(5 * count)

    # AIR sumcheck has degree 11 and `maximum` rounds.
    for _ in range(maximum):
        consume(5 * 12)
    for count in [22, 42, 110]:
        consume(5 * count)

    cross_values = consume(5 * 2)
    batching_pow = consume(1)
    combined_ood = consume(5 * fixture["whir"]["commitment_ood_samples"])

    whir = fixture["whir"]
    for _ in range(fixture["profiles"]["node"]["first_folding_factor"]):
        consume(5 * 3)
        if whir["starting_folding_pow_bits"]:
            consume(1)
    for round_config in whir["rounds"]:
        consume(8)
        consume(5 * round_config["ood_samples"])
        if round_config["query_pow_bits"]:
            consume(1)
        for _ in range(fixture["profiles"]["node"]["subsequent_folding_factor"]):
            consume(5 * 3)
            if round_config["folding_pow_bits"]:
                consume(1)
    consume(5 * (1 << whir["final_sumcheck_rounds"]))
    if whir["final_round"]["query_pow_bits"]:
        consume(1)
    for _ in range(whir["final_sumcheck_rounds"]):
        consume(5 * 3)

    assert offset == len(raw), "raw transcript does not match complete selected verifier consumption"
    return {
        "dimensions": 0,
        "primary_commitment": primary_root,
        "secondary_commitment": secondary_root,
        "cross_values": cross_values,
        "batching_pow": batching_pow,
        "combined_ood": combined_ood,
        "consumed_fields": offset,
    }


def validate_fixture(path):
    fixture = json.loads(path.read_text())
    assert fixture["schema"] == SCHEMA
    assert fixture["mode"] == MODE
    assert fixture["hash_backend"] == HASH_BACKEND
    assert fixture["base_field_modulus"] == MODULUS
    assert fixture["extension_degree"] == 5
    assert fixture["extension_polynomial"] == "X^5 + X^2 - 1"
    assert fixture["native_verification"] == (
        "passed, including the integrated fixed-program commitment and all three bytecode claims"
    )
    profiles = fixture["profiles"]
    assert profiles["terminal_keccak"] is True
    assert profiles["terminal_public_memory"] is True
    assert profiles["terminal_two_commitment"] is True
    node_profile = profiles["node"]
    # The verifier family is pinned; the grinding budget and final-coefficient
    # threshold are schedule knobs bound into the recomputed capacity below.
    assert node_profile["security_bits"] == 100
    assert node_profile["first_folding_factor"] == 5
    assert node_profile["subsequent_folding_factor"] == 4
    assert node_profile["rs_domain_initial_reduction_factor"] == 1
    assert node_profile["log_inv_rate"] == 6
    assert 0 < node_profile["grinding_bits"] <= 30
    assert (
        node_profile["subsequent_folding_factor"] - 1
        <= node_profile["max_num_variables_to_send_coeffs"]
        <= 10
    )

    validate_base_array(fixture["application_root"], 8, "application root")
    validate_base_array(fixture["public_input"], 8, "public input")
    validate_base_array(fixture["fiat_shamir_cap"], 8, "Fiat-Shamir capacity")
    assert fixture["application_root"] == fixture["public_input"]

    programs = fixture["bytecodes"]
    assert [program["program"] for program in programs] == list(PROGRAMS)
    assert [program["mle_num_variables"] for program in programs] == PROGRAM_DIMENSIONS
    assert [program["mle_fields"] for program in programs] == [1 << x for x in PROGRAM_DIMENSIONS]
    assert [program["log_instructions"] for program in programs] == [18, 17, 17]
    assert all(program["ending_pc"] == (1 << program["log_instructions"]) - 1 for program in programs)
    assert fixture["measurement"]["bytecode_hash"] == programs[2]["hash"]
    for program in programs:
        validate_base_array(program["hash"], 8, f"{program['program']} bytecode hash")
        mle_file = path.parent / program["mle_file"]
        assert mle_file.is_file(), mle_file
        assert mle_file.stat().st_size == 4 * program["mle_fields"]
        assert sha256(mle_file) == program["mle_sha256"]

    claims = fixture["bytecode_claims"]
    assert sorted(claims) == sorted(PROGRAMS)
    for name, dimension in zip(PROGRAMS, PROGRAM_DIMENSIONS):
        claim = claims[name]
        assert len(claim["point"]) == dimension
        for i, coordinate in enumerate(claim["point"]):
            validate_extension(coordinate, f"{name} point {i}")
        validate_extension(claim["value"], f"{name} value")

    public_memory = fixture["public_memory_region"]
    assert public_memory["domain"] == 0x50554D31
    assert public_memory["start"] == 4096
    assert public_memory["values"] == fixture["node_info"]
    assert len(public_memory["values"]) == 256
    lift = flatten_claim(claims["lift"])
    spark = flatten_claim(claims["spark"])
    assert len(lift) == 112 and len(spark) == 120
    lifted_capacity = public_memory["values"][120:128]
    validate_base_array(lifted_capacity, 8, "lifted verifier capacity")
    expected_public_memory = [0x4E4F4431, 2] + [0] * 6
    expected_public_memory.extend(lift)
    expected_public_memory.extend(lifted_capacity)
    expected_public_memory.extend(spark)
    expected_public_memory.extend(fixture["application_root"])
    assert expected_public_memory == public_memory["values"]

    c1 = fixture["two_commitment_whir"]
    assert c1["protocol_mode_tag"] == MODE_TAG
    assert c1["fiat_shamir_cap_scope"] == CAP_SCOPE
    assert c1["two_commitment_batching_pow_bits"] == 2
    assert c1["execution_bytecode_point_prefix"] == [1, 1]
    assert c1["secondary_statement_public_memory_offsets"] == STATEMENT_MEMORY_OFFSETS
    bindings = c1["secondary_statement_public_memory_bindings"]
    assert [binding["public_memory_offset"] for binding in bindings] == STATEMENT_MEMORY_OFFSETS
    assert [point_prefix_length(binding) for binding in bindings] == [1, 2]
    assert [binding["point_prefix"] for binding in bindings] == STATEMENT_PREFIXES
    descriptor_length, descriptor = expected_static_descriptor(c1)
    assert descriptor_length == 47 and len(descriptor) == 48
    exported_descriptor = c1["static_descriptor"]
    assert exported_descriptor["field_count_before_padding"] == descriptor_length
    assert exported_descriptor["padded_field_count"] == len(descriptor)
    assert exported_descriptor["fields"] == descriptor
    assert recompute_c1_capacity(programs[2]["hash"], profiles["node"], descriptor) == fixture[
        "fiat_shamir_cap"
    ]

    primary = c1["primary"]
    secondary = c1["secondary"]
    assert primary["num_variables"] == 23
    assert primary["actual_data_len"] == fixture["measurement"]["stacked_entries"]
    assert secondary["layout"] == list(PROGRAMS)
    assert secondary["program_dimensions"] == PROGRAM_DIMENSIONS
    assert secondary["num_variables"] == 23
    assert secondary["actual_data_len"] == 1 << 23
    assert sum(program["mle_fields"] for program in programs) == secondary["actual_data_len"]
    validate_digest(secondary["trusted_root"], "fixed-program commitment")
    assert fixture["raw_transcript"][16:24] == secondary["trusted_root"]

    observation = c1["statement_observation"]
    assert observation["tag"] == STATEMENT_TAG
    assert observation["field_count"] == 254
    assert observation["field_count"] == len(observation["fields"])
    assert observation["fields"] == expected_statement_observation(claims, 23)
    assert observation["transcript_order"] == (
        "after public input and public memory; before dimensions and both commitment roots"
    )

    whir = fixture["whir"]
    assert whir["num_variables"] == 23
    assert whir["commitment_ood_samples"] == 1
    assert whir["starting_log_inv_rate"] == 6
    assert whir["starting_folding_pow_bits"] <= node_profile["grinding_bits"]
    assert whir["rs_domain_initial_reduction_factor"] == 1
    assert whir["final_sumcheck_rounds"] <= node_profile["max_num_variables_to_send_coeffs"]
    assert whir["final_sumcheck_rounds"] == 23 - node_profile["first_folding_factor"] - len(
        whir["rounds"]
    ) * node_profile["subsequent_folding_factor"]

    roles, queries, widths, heights = expected_opening_batches(
        whir, node_profile["first_folding_factor"], node_profile["subsequent_folding_factor"]
    )
    batches = c1["opening_batches"]
    assert len(batches) == len(roles)
    assert [batch["role"] for batch in batches] == roles
    assert [batch["num_queries"] for batch in batches] == queries
    assert [batch["leaf_fields"] for batch in batches] == widths
    assert [batch["merkle_height"] for batch in batches] == heights
    raw_offset = 0
    raw_openings = fixture["merkle_openings"]
    for batch in batches:
        assert batch["raw_opening_offset"] == raw_offset
        end = raw_offset + batch["num_queries"]
        selected = raw_openings[raw_offset:end]
        assert len(selected) == batch["num_queries"]
        assert all(len(opening["leaf_data"]) == batch["leaf_fields"] for opening in selected)
        assert all(len(opening["path"]) == batch["merkle_height"] for opening in selected)
        for opening in selected:
            assert all(type(value) is int and 0 <= value < MODULUS for value in opening["leaf_data"])
            for digest in opening["path"]:
                validate_digest(digest, "Merkle sibling")
        raw_offset = end
    assert raw_offset == len(raw_openings) == sum(queries)

    proof_name = fixture["proof_file"]
    assert Path(proof_name).name == proof_name
    proof_path = path.parent / proof_name
    proof_hash = sha256(proof_path)
    assert fixture["proof_bytes"] == proof_path.stat().st_size
    assert fixture["proof_sha256"] == proof_hash
    compact = c1["compact_execution_proof"]
    assert compact["file"] == proof_name
    assert compact["bytes"] == fixture["proof_bytes"]
    assert compact["sha256"] == proof_hash
    assert compact["raw_transcript_fields"] == len(fixture["raw_transcript"])
    assert compact["raw_transcript_u32le_bytes"] == 4 * len(fixture["raw_transcript"])
    assert compact["raw_merkle_openings"] == len(raw_openings)
    assert len(fixture["raw_transcript"]) % 8 == 0
    assert all(type(value) is int and 0 <= value < MODULUS for value in fixture["raw_transcript"])

    offsets = transcript_layout(fixture)
    return fixture, programs, claims, lifted_capacity, proof_path, offsets


def pruned_openings(fixture, proof_path):
    reader = PostcardProof(proof_path.read_bytes())
    compressed_transcript = reader.vector(reader.field)
    groups = reader.vector(
        lambda: {
            "rows": reader.vector(lambda: reader.vector(reader.field)),
            "siblings": reader.vector(lambda: [reader.field() for _ in range(8)]),
        }
    )
    assert reader.offset == len(reader.data), "unused native proof bytes"
    batches = fixture["two_commitment_whir"]["opening_batches"]
    assert len(groups) == len(batches), "native multiproof group count"

    output = bytearray()
    encoded_groups = []
    raw_openings = fixture["merkle_openings"]
    for group, batch in zip(groups, batches):
        start = len(output)
        raw_start = batch["raw_opening_offset"]
        raw = raw_openings[raw_start:raw_start + batch["num_queries"]]
        rows = group["rows"]
        assert rows and len(rows) <= len(raw)
        sent_width = len(rows[0])
        assert sent_width <= batch["leaf_fields"]
        assert all(len(row) == sent_width for row in rows)
        full_rows = [row + [0] * (batch["leaf_fields"] - sent_width) for row in rows]
        assert set(map(tuple, full_rows)) == {tuple(opening["leaf_data"]) for opening in raw}, (
            "native rows disagree with raw export",
            batch["role"],
        )
        raw_siblings = {tuple(digest) for opening in raw for digest in opening["path"]}
        assert all(tuple(digest) in raw_siblings for digest in group["siblings"]), (
            "native siblings disagree with raw export",
            batch["role"],
        )
        for row in full_rows:
            output.extend(b"".join(int(value).to_bytes(4, "big") for value in row))
        for digest in group["siblings"]:
            output.extend(limbs_digest(digest)[:30])
        encoded_groups.append(
            {
                "role": batch["role"],
                "offset": start,
                "bytes": len(output) - start,
                "unique_rows": len(full_rows),
                "native_row_fields": sent_width,
                "encoded_row_fields": batch["leaf_fields"],
                "sibling_digests": len(group["siblings"]),
            }
        )
    return bytes(output), encoded_groups, len(compressed_transcript)


def packed_claim(claim):
    return [packed_extension(coordinate) for coordinate in claim["point"]], packed_extension(claim["value"])


def safe_low_byte_xor(value):
    for mask in (1, 2, 4, 8):
        if value ^ mask < MODULUS:
            return mask
    raise AssertionError("could not choose a canonical transcript mutation")


def generated_contract(contract, fixture, programs, lifted_capacity):
    c1 = fixture["two_commitment_whir"]
    bindings = c1["secondary_statement_public_memory_bindings"]
    prefixes = [packed_extension(value) for binding in bindings for value in binding["point_prefix"]]
    assert prefixes == [0, ONE_PACKED, 0]
    code = f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {{ LeanVmTwoCommitmentTerminalVerifier }} from "../LeanVmTwoCommitmentTerminalVerifier.sol";
import {{ LeanVmTwoCommitmentExecution as Execution }} from "../LeanVmTwoCommitmentExecution.sol";
import {{ LeanVmWhir as Whir }} from "../LeanVmWhir.sol";

contract {contract} is LeanVmTwoCommitmentTerminalVerifier {{
    function rootConfig()
        internal
        pure
        virtual
        override
        returns (Execution.Config memory config)
    {{
        config.bytecodeLog = {programs[2]['log_instructions']};
        config.endingPc = {programs[2]['ending_pc']};
        config.rate = {fixture['profiles']['node']['log_inv_rate']};
        config.capacity = {array_literal(fixture['fiat_shamir_cap'])};
'''
    code += "\n".join("        " + line for line in config_lines(
        "config.whir", fixture["whir"], fixture["profiles"]["node"], "multiproof30"
    ).splitlines())
    code += f'''
    }}

    function fixedProgramConfig()
        internal
        pure
        virtual
        override
        returns (Execution.TwoCommitmentConfig memory config)
    {{
        config.modeTag = {c1['protocol_mode_tag']};
        config.batchingPowBits = {c1['two_commitment_batching_pow_bits']};
        config.programDimensions = {array_literal(c1['secondary']['program_dimensions'])};
        config.secondaryActualDataLength = {c1['secondary']['actual_data_len']};
        config.secondaryStatementPublicMemoryOffsets = {array_literal(c1['secondary_statement_public_memory_offsets'])};
        config.secondaryStatementPointPrefixLengths = {array_literal([point_prefix_length(binding) for binding in bindings])};
        config.secondaryStatementPointPrefixes = {array_literal(prefixes)};
        config.executionBytecodePointPrefix = {array_literal([ONE_PACKED, ONE_PACKED])};
        config.expectedSecondaryRoot = {array_literal(c1['secondary']['trusted_root'])};
    }}

    function liftedCapacity()
        internal
        pure
        virtual
        override
        returns (uint256[8] memory)
    {{
        return {array_literal(lifted_capacity)};
    }}
}}
'''
    return code


def generated_test(
    contract, label, transcript_offsets, opening_groups, opening_bytes, raw_transcript, claims
):
    cross = 4 * transcript_offsets["cross_values"]
    ood = 4 * transcript_offsets["combined_ood"]
    cross_mask = safe_low_byte_xor(raw_transcript[transcript_offsets["cross_values"]])
    ood_mask = safe_low_byte_xor(raw_transcript[transcript_offsets["combined_ood"]])
    primary_opening = opening_groups[0]["offset"] + 3
    secondary_opening = opening_groups[1]["offset"] + 3
    primary_opening_mask = safe_low_byte_xor(int.from_bytes(opening_bytes[:4], "big"))
    secondary_start = opening_groups[1]["offset"]
    secondary_opening_mask = safe_low_byte_xor(
        int.from_bytes(opening_bytes[secondary_start:secondary_start + 4], "big")
    )
    spark_point_mask = safe_low_byte_xor(claims["spark"]["point"][0][0])
    spark_value_mask = safe_low_byte_xor(claims["spark"]["value"][0])
    lift_point_mask = safe_low_byte_xor(claims["lift"]["point"][0][0])
    lift_value_mask = safe_low_byte_xor(claims["lift"]["value"][0])
    root_value_mask = safe_low_byte_xor(claims["root"]["value"][0])
    return f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {{ Test, console2 }} from "forge-std/Test.sol";
import {{ LeanVmTwoCommitmentTerminalVerifier }} from "../src/leanvm/LeanVmTwoCommitmentTerminalVerifier.sol";
import {{ LeanVmTwoCommitmentExecution as Execution }} from "../src/leanvm/LeanVmTwoCommitmentExecution.sol";
import {{ {contract} }} from "../src/leanvm/generated/{contract}.sol";

contract {contract}WrongRoot is {contract} {{
    function fixedProgramConfig()
        internal
        pure
        override
        returns (Execution.TwoCommitmentConfig memory config)
    {{
        config = super.fixedProgramConfig();
        config.expectedSecondaryRoot[0] ^= 1;
    }}
}}

contract {contract}Test is Test {{
    {contract} private verifier;

    function setUp() external {{
        verifier = new {contract}();
    }}

    function loadProof()
        internal
        view
        returns (LeanVmTwoCommitmentTerminalVerifier.Proof memory)
    {{
        return abi.decode(
            vm.readFileBinary("testdata/leanvm_terminal/{label}/proof.abi"),
            (LeanVmTwoCommitmentTerminalVerifier.Proof)
        );
    }}

    function testCompleteTwoCommitmentTerminal() external view {{
        uint256 beforeGas = gasleft();
        require(verifier.verifyC1V1(loadProof()), "VERIFY");
        console2.log("complete two-commitment terminal call gas", beforeGas - gasleft());
    }}

    function testRejectApplicationRoot() external {{
        LeanVmTwoCommitmentTerminalVerifier.Proof memory proof = loadProof();
        proof.applicationRoot[0] ^= 1;
        vm.expectRevert();
        verifier.verifyC1V1(proof);
    }}

    function testRejectSparkPoint() external {{
        LeanVmTwoCommitmentTerminalVerifier.Proof memory proof = loadProof();
        proof.sparkPoint[0] ^= uint256({spark_point_mask}) << 224;
        vm.expectRevert();
        verifier.verifyC1V1(proof);
    }}

    function testRejectSparkValue() external {{
        LeanVmTwoCommitmentTerminalVerifier.Proof memory proof = loadProof();
        proof.sparkValue ^= uint256({spark_value_mask}) << 224;
        vm.expectRevert();
        verifier.verifyC1V1(proof);
    }}

    function testRejectLiftPoint() external {{
        LeanVmTwoCommitmentTerminalVerifier.Proof memory proof = loadProof();
        proof.liftPoint[0] ^= uint256({lift_point_mask}) << 224;
        vm.expectRevert();
        verifier.verifyC1V1(proof);
    }}

    function testRejectLiftValue() external {{
        LeanVmTwoCommitmentTerminalVerifier.Proof memory proof = loadProof();
        proof.liftValue ^= uint256({lift_value_mask}) << 224;
        vm.expectRevert();
        verifier.verifyC1V1(proof);
    }}

    function testRejectRootValue() external {{
        LeanVmTwoCommitmentTerminalVerifier.Proof memory proof = loadProof();
        proof.rootValue ^= uint256({root_value_mask}) << 224;
        vm.expectRevert();
        verifier.verifyC1V1(proof);
    }}

    function testRejectPrimaryCommitment() external {{
        LeanVmTwoCommitmentTerminalVerifier.Proof memory proof = loadProof();
        proof.transcript[{4 * transcript_offsets['primary_commitment']}] ^= bytes1(0x01);
        vm.expectRevert();
        verifier.verifyC1V1(proof);
    }}

    function testRejectSecondaryCommitment() external {{
        LeanVmTwoCommitmentTerminalVerifier.Proof memory proof = loadProof();
        proof.transcript[{4 * transcript_offsets['secondary_commitment']}] ^= bytes1(0x01);
        vm.expectRevert("FIXED_PROGRAM_ROOT");
        verifier.verifyC1V1(proof);
    }}

    function testRejectPrimaryInitialOpening() external {{
        LeanVmTwoCommitmentTerminalVerifier.Proof memory proof = loadProof();
        proof.openings[{primary_opening}] ^= bytes1(uint8({primary_opening_mask}));
        vm.expectRevert("MERKLE_ROOT");
        verifier.verifyC1V1(proof);
    }}

    function testRejectSecondaryInitialOpening() external {{
        LeanVmTwoCommitmentTerminalVerifier.Proof memory proof = loadProof();
        proof.openings[{secondary_opening}] ^= bytes1(uint8({secondary_opening_mask}));
        vm.expectRevert("MERKLE_ROOT");
        verifier.verifyC1V1(proof);
    }}

    function testRejectCrossValue() external {{
        LeanVmTwoCommitmentTerminalVerifier.Proof memory proof = loadProof();
        proof.transcript[{cross}] ^= bytes1(uint8({cross_mask}));
        vm.expectRevert();
        verifier.verifyC1V1(proof);
    }}

    function testRejectCombinedOodValue() external {{
        LeanVmTwoCommitmentTerminalVerifier.Proof memory proof = loadProof();
        proof.transcript[{ood}] ^= bytes1(uint8({ood_mask}));
        vm.expectRevert();
        verifier.verifyC1V1(proof);
    }}

    function testRejectWrongTrustedRoot() external {{
        {contract}WrongRoot wrong = new {contract}WrongRoot();
        vm.expectRevert("FIXED_PROGRAM_ROOT");
        wrong.verifyC1V1(loadProof());
    }}

    function testRejectTrailingTranscript() external {{
        LeanVmTwoCommitmentTerminalVerifier.Proof memory proof = loadProof();
        proof.transcript = bytes.concat(proof.transcript, new bytes(32));
        vm.expectRevert("UNUSED_TRANSCRIPT");
        verifier.verifyC1V1(proof);
    }}

    function testRejectTrailingOpenings() external {{
        LeanVmTwoCommitmentTerminalVerifier.Proof memory proof = loadProof();
        proof.openings = bytes.concat(proof.openings, new bytes(32));
        vm.expectRevert("UNUSED_OPENINGS");
        verifier.verifyC1V1(proof);
    }}
}}
'''


def generated_benchmark(contract, label):
    return f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {{ Script, console2 }} from "forge-std/Script.sol";
import {{ LeanVmTwoCommitmentTerminalVerifier }} from "../src/leanvm/LeanVmTwoCommitmentTerminalVerifier.sol";
import {{ {contract} }} from "../src/leanvm/generated/{contract}.sol";

contract {contract}TxBenchmark is Script {{
    function run() external {{
        bytes memory encoded =
            vm.readFileBinary("testdata/leanvm_terminal/{label}/proof.abi");
        LeanVmTwoCommitmentTerminalVerifier.Proof memory proof = abi.decode(
            encoded, (LeanVmTwoCommitmentTerminalVerifier.Proof)
        );
        bytes memory data =
            vm.readFileBinary("testdata/leanvm_terminal/{label}/calldata.bin");
        require(
            keccak256(data)
                == keccak256(
                    abi.encodeCall(LeanVmTwoCommitmentTerminalVerifier.verifyC1V1, (proof))
                ),
            "CALLDATA_ENCODING"
        );
        vm.startBroadcast();
        {contract} verifier = new {contract}();
        (bool ok, bytes memory result) = address(verifier).call(data);
        require(ok && abi.decode(result, (bool)), "VERIFY_FAILED");
        vm.stopBroadcast();
        console2.log("complete two-commitment terminal verifier", address(verifier));
        console2.log("complete verification calldata bytes", data.length);
    }}
}}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root_fixture", type=Path)
    parser.add_argument("label")
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args()
    assert args.label.replace("_", "").isalnum() and args.label[0].isalpha()

    fixture, programs, claims, lifted_capacity, proof_path, transcript_offsets = validate_fixture(
        args.root_fixture
    )
    opening_bytes, opening_groups, compressed_transcript_fields = pruned_openings(
        fixture, proof_path
    )
    validation = {
        "schema": fixture["schema"],
        "proof_sha256": fixture["proof_sha256"],
        "proof_bytes": fixture["proof_bytes"],
        "raw_transcript_fields": len(fixture["raw_transcript"]),
        "compressed_transcript_fields": compressed_transcript_fields,
        "opening_groups": opening_groups,
        "transcript_offsets_fields": transcript_offsets,
    }
    if args.validate_only:
        print(json.dumps(validation, indent=2))
        return

    label = args.label
    contract = "LeanVmTwoCommitmentTerminal_" + label
    source = REPO / "src/leanvm/generated" / f"{contract}.sol"
    test = REPO / "test" / f"{contract}.t.sol"
    benchmark = REPO / "script" / f"{contract}.s.sol"
    data = REPO / "testdata/leanvm_terminal" / label
    for output in [source, test, benchmark, data]:
        assert not output.exists(), f"output already exists: {output}"
    source.parent.mkdir(parents=True, exist_ok=True)
    data.mkdir(parents=True)

    raw_transcript = fixture["raw_transcript"]
    transcript_bytes = b"".join(int(value).to_bytes(4, "little") for value in raw_transcript)
    spark_point, spark_value = packed_claim(claims["spark"])
    lift_point, lift_value = packed_claim(claims["lift"])
    _, root_value = packed_claim(claims["root"])
    proof = tuple_encoding(
        [
            (True, dynamic_bytes(transcript_bytes)),
            (True, dynamic_bytes(opening_bytes)),
            (False, b"".join(word(value) for value in fixture["application_root"])),
            (True, word(len(spark_point)) + b"".join(word(value) for value in spark_point)),
            (False, word(spark_value)),
            (True, word(len(lift_point)) + b"".join(word(value) for value in lift_point)),
            (False, word(lift_value)),
            (False, word(root_value)),
        ]
    )
    encoded = tuple_encoding([(True, proof)])
    signature = "verifyC1V1((bytes,bytes,uint256[8],uint256[],uint256,uint256[],uint256,uint256))"
    calldata = keccak256(signature.encode())[:4] + encoded

    source.write_text(generated_contract(contract, fixture, programs, lifted_capacity))
    test.write_text(
        generated_test(
            contract,
            label,
            transcript_offsets,
            opening_groups,
            opening_bytes,
            raw_transcript,
            claims,
        )
    )
    benchmark.write_text(generated_benchmark(contract, label))
    (data / "proof.abi").write_bytes(encoded)
    (data / "calldata.bin").write_bytes(calldata)

    source_files = list((REPO / "src/leanvm").glob("*.sol")) + [
        source,
        test,
        benchmark,
        REPO / "src/field/KoalaBear.sol",
        REPO / "src/field/KoalaBearExt5.sol",
        REPO / "src/field/KoalaBearPackedField.sol",
        REPO / "src/transcript/KeccakChallenger.sol",
        REPO / "foundry.toml",
        Path(__file__).with_name("leanvm_terminal_fixture_codec.py"),
        Path(__file__).resolve(),
    ]
    manifest = {
        "schema": "leanvm-terminal-two-commitment-solidity-fixture-v1",
        "native_fixture_schema": fixture["schema"],
        "native_root_fixture_sha256": sha256(args.root_fixture),
        "native_proof_sha256": fixture["proof_sha256"],
        "contract": contract,
        "entry_point": "verifyC1V1",
        "abi_argument_bytes": len(encoded),
        "calldata_bytes": len(calldata),
        "calldata_zero_bytes": calldata.count(0),
        "calldata_nonzero_bytes": len(calldata) - calldata.count(0),
        "calldata_gas_4_16": sum(4 if value == 0 else 16 for value in calldata),
        "verification_selector": calldata[:4].hex(),
        "proof_abi_sha256": hashlib.sha256(encoded).hexdigest(),
        "calldata_sha256": hashlib.sha256(calldata).hexdigest(),
        "transcript_bytes": len(transcript_bytes),
        "transcript_offsets_fields": transcript_offsets,
        "transcript_offsets_bytes": {
            key: 4 * value for key, value in transcript_offsets.items() if key != "consumed_fields"
        },
        "openings_bytes": len(opening_bytes),
        "opening_groups": opening_groups,
        "openings_codec": "multiproof30",
        "hash_backend": fixture["hash_backend"],
        "fiat_shamir_cap": fixture["fiat_shamir_cap"],
        "two_commitment_whir": fixture["two_commitment_whir"],
        "programs": programs,
        "root_profile": fixture["profiles"]["node"],
        "source_sha256": {
            str(path.relative_to(REPO)): sha256(path) for path in sorted(set(source_files))
        },
    }
    (data / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(
        json.dumps(
            {
                "contract": contract,
                "abi_argument_bytes": len(encoded),
                "calldata_bytes": len(calldata),
                "calldata_gas_4_16": manifest["calldata_gas_4_16"],
                "source": str(source.relative_to(REPO)),
                "test": str(test.relative_to(REPO)),
                "benchmark": str(benchmark.relative_to(REPO)),
                "data": str(data.relative_to(REPO)),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
