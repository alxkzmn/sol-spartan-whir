"""Shared encoders for LeanVM Solidity terminal fixtures."""

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "research/2026-09-09-withdrawal-chain/terminal"))
from terminal_hashes import keccak256, limbs_digest  # noqa: E402


def word(value):
    return int(value).to_bytes(32, "big")


def dynamic_bytes(data):
    return word(len(data)) + data + bytes(-len(data) % 32)


def tuple_encoding(items):
    head_size = sum(32 if dynamic else len(data) for dynamic, data in items)
    head = b""
    tail = b""
    for dynamic, data in items:
        if dynamic:
            head += word(head_size + len(tail))
            tail += data
        else:
            head += data
    return head + tail


def packed_extension(values):
    assert len(values) == 5 and all(0 <= value < 2_130_706_433 for value in values)
    return sum(value << (224 - index * 32) for index, value in enumerate(values))


class PostcardProof:
    """Read the native Proof's vectors; KoalaBear serde stores Montgomery u32s."""

    MODULUS = 2_130_706_433
    INVERSE_R = pow(pow(2, 32, MODULUS), -1, MODULUS)

    def __init__(self, data):
        self.data = data
        self.offset = 0

    def integer(self):
        value = 0
        shift = 0
        while True:
            assert self.offset < len(self.data) and shift < 64, "invalid postcard integer"
            byte = self.data[self.offset]
            self.offset += 1
            value |= (byte & 127) << shift
            if byte < 128:
                return value
            shift += 7

    def field(self):
        value = self.integer()
        assert value < self.MODULUS, "noncanonical native field"
        return value * self.INVERSE_R % self.MODULUS

    def vector(self, read):
        count = self.integer()
        assert count <= len(self.data) - self.offset, "invalid postcard vector length"
        return [read() for _ in range(count)]


def array_literal(values):
    return "[uint256(" + str(values[0]) + ")," + ",".join(map(str, values[1:])) + "]"


def round_literal(round_config):
    fields = (
        "num_variables",
        "folding_factor",
        "domain_size",
        "folded_domain_gen",
        "num_queries",
        "ood_samples",
        "query_pow_bits",
        "folding_pow_bits",
    )
    return "Whir.Round(" + ",".join(str(round_config[field]) for field in fields) + ")"


def config_lines(target, config, profile, openings_codec="full-paths"):
    assignments = (
        ("variables", config["num_variables"]),
        ("firstFold", profile["first_folding_factor"]),
        ("nextFold", profile["subsequent_folding_factor"]),
        ("commitmentOod", config["commitment_ood_samples"]),
        ("firstPow", config["starting_folding_pow_bits"]),
        ("finalRounds", config["final_sumcheck_rounds"]),
    )
    output = [f"{target}.{name}={value};" for name, value in assignments]
    output.append(f'{target}.rounds=new Whir.Round[]({len(config["rounds"])});')
    for index, round_config in enumerate(config["rounds"]):
        output.append(f"{target}.rounds[{index}]={round_literal(round_config)};")
    output.append(f'{target}.finalRound={round_literal(config["final_round"])};')
    if openings_codec == "multiproof30":
        output.append(f"{target}.openingsCodec=1;")
    return "\n".join(output)