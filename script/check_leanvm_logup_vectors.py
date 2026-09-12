#!/usr/bin/env python3
"""Check native LogUp/GKR fixtures with the independent Python verifier and Keccak adapter."""

import argparse
import importlib.util
import json
from pathlib import Path
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    project = Path(__file__).resolve().parents[1]
    parser.add_argument("--vectors", type=Path, default=project / "testdata/leanvm_logup/vectors.json")
    parser.add_argument("--adapter", type=Path, default=project.parent / "research/2026-09-09-withdrawal-chain/terminal/verify_root_fixture.py")
    args = parser.parse_args()
    sys.path.insert(0, str(args.adapter.parent))
    spec = importlib.util.spec_from_file_location("leanvm_logup_reference_adapter", args.adapter)
    adapter = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = adapter
    spec.loader.exec_module(adapter)
    import verifier as reference

    def encode(value):
        return [coordinate.value for coordinate in value.c]

    def initial(vector, field, replacement=None):
        data = replacement if replacement is not None else bytes.fromhex(vector[field][2:])
        assert len(data) % 4 == 0
        words = [int.from_bytes(data[i:i + 4], "little") for i in range(0, len(data), 4)]
        assert all(value < reference.P for value in words), "noncanonical input"
        assert any(words[160:165]), "zero initial GKR denominator"
        proof = reference.Proof([reference.Fp(x) for x in words], [])
        fs = adapter.KeccakFiatShamir(proof, [reference.Fp(x) for x in vector["capacity"]])
        gamma = fs.sample_ef()
        fs.duplex()
        beta = fs.sample_many_ef(4)
        assert encode(gamma) == vector["gamma"]
        assert [encode(x) for x in beta] == vector["beta"]
        return fs, gamma, beta, reference.eval_eq(beta)

    def logup(vector, replacement=None):
        fs, gamma, beta, beta_eq = initial(vector, "transcript", replacement)
        heights = {table.name: height for table, height in zip(reference.TABLES, vector["heights"])}
        result = reference.verify_logup(fs, gamma, beta, beta_eq, vector["memory_log"], vector["bytecode"], reference.TABLES, heights)
        memory, memory_acc, code_acc, nums, dens, point, columns = result
        assert encode(memory) == vector["memory_value"]
        assert encode(memory_acc) == vector["memory_acc"]
        assert encode(code_acc) == vector["value_bytecode_acc"]
        assert [encode(x) for x in point] == vector["gkr_point"]
        for index, table in enumerate(reference.TABLES):
            assert encode(nums[table.name]) == vector["numerators"][index]
            assert encode(dens[table.name]) == vector["denominators"][index]
            expected = dict(zip(vector["column_indices"][index], vector["columns"][index]))
            assert {i: encode(value) for i, value in columns[table.name].items()} == expected
        fixed_point = point[-vector["bytecode_log"]:] + beta
        assert [encode(x) for x in fixed_point] == vector["fixed_bytecode_point"]
        assert encode(reference.eval_multilinear_by_evals([reference.Fp(x) for x in vector["bytecode"]], fixed_point)) == vector["fixed_bytecode_value"]
        assert fs.offset == len(fs.transcript)
        assert encode(fs.sample_ef()) == vector["post_logup_sample"]

    def gkr(vector, replacement=None):
        fs, _, _, _ = initial(vector, "gkr_transcript", replacement)
        quotient, point, numerator, denominator = reference.verify_gkr_quotient(fs, vector["gkr_n_vars"])
        assert encode(quotient) == vector["gkr_quotient"]
        assert encode(numerator) == vector["gkr_numerator"]
        assert encode(denominator) == vector["gkr_denominator"]
        assert [encode(x) for x in point] == vector["gkr_point"]
        assert fs.offset == len(fs.transcript)
        assert encode(fs.sample_ef()) == vector["post_gkr_sample"]

    vectors = json.loads(args.vectors.read_text())["vectors"]
    for vector in vectors:
        gkr(vector)
        logup(vector)
    vector = vectors[0]
    rejected = []

    def reject(name, verify, data):
        try:
            verify(vector, data)
        except (AssertionError, ValueError, IndexError, ZeroDivisionError):
            rejected.append(name)
        else:
            raise AssertionError(f"accepted mutation {name}")

    gkr_data = bytes.fromhex(vector["gkr_transcript"][2:])
    logup_data = bytes.fromhex(vector["transcript"][2:])

    def change(data, index, replacement=None):
        result = bytearray(data)
        before = int.from_bytes(result[index * 4:index * 4 + 4], "little")
        after = (before + 1) % reference.P if replacement is None else replacement
        result[index * 4:index * 4 + 4] = after.to_bytes(4, "little")
        return bytes(result)

    reject("sumcheck", gkr, change(gkr_data, 320))
    reject("deferred_child", gkr, change(gkr_data, len(gkr_data) // 4 - 24))
    reject("padding", gkr, change(gkr_data, 340, 1))
    reject("noncanonical", gkr, change(gkr_data, 0, reference.P))
    reject("trailing", gkr, gkr_data + bytes(4))
    reject("truncated", gkr, gkr_data[:-4])
    zero_denominator = bytearray(gkr_data)
    zero_denominator[160 * 4:165 * 4] = bytes(20)
    reject("zero_denominator", gkr, bytes(zero_denominator))
    for index, name in enumerate(["memory_acc", "memory", "bytecode_acc", "precompile_num", "precompile_den"]):
        reject(name, logup, change(logup_data, len(gkr_data) // 4 + index * 8))
    print(json.dumps({"native_vectors": len(vectors), "gkr_python_passed": len(vectors), "logup_python_passed": len(vectors), "rejected_mutations": rejected}, indent=2))


if __name__ == "__main__":
    main()
