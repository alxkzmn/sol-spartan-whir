#!/usr/bin/env python3
"""Generate a typed standalone-WHIR verifier and tests for an exported schedule."""
import argparse
import json
import re
import shutil
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    report = json.loads((args.fixture / "report.json").read_text())
    if report["schema"] != "standalone-whir-schedule-export-v1":
        raise ValueError("unexpected fixture schema")
    label = report["label"]
    if re.fullmatch(r"k[0-9]+_pow[0-9]+_ff[0-9]+_rest[0-9]+_lir[0-9]+_rsv[0-9]+", label) is None:
        raise ValueError("unexpected schedule label")
    library = "QuinticWhirFixedConfig_" + label
    config = (args.fixture / (library + ".sol")).read_text()
    if "COMMITMENT_OOD_SAMPLES = 1;" not in config:
        raise ValueError("typed schedule verifier currently supports one initial OOD sample")
    original = "k22_jb100_ext5_lir4_ff4_rsv3_pow28"
    source_dir = root / "src/whir" / original
    source = (source_dir / ("WhirVerifier5_" + original + ".sol")).read_text()
    source = source.replace(original, label)
    source = source.replace('from "./WhirVerifierCore5.sol"', 'from "../' + original + '/WhirVerifierCore5.sol"')
    source = source.replace('from "./WhirVerifierUtils5.sol"', 'from "../' + original + '/WhirVerifierUtils5.sol"')
    start = source.index("        uint256 round0ConstraintChallenge;")
    end = source.index("        if (statement.points.length", start)
    source = source[:start] + """        uint256[] memory roundChallenges = new uint256[](QuinticWhirFixedConfig.ROUND_COUNT);
        uint256[][] memory roundEqPoints = new uint256[][](QuinticWhirFixedConfig.ROUND_COUNT);
        uint256[][] memory roundSelVars = new uint256[][](QuinticWhirFixedConfig.ROUND_COUNT);

""" + source[end:]
    start = source.index("                if (i == 0) {")
    end = source.index("                (claimedEval, foldingRandomness, randomnessCursor)", start)
    source = source[:start] + """                roundChallenges[i] = roundConstraintChallenge;
                roundEqPoints[i] = nextCommitment.oodStatement.flatPoints;
                roundSelVars[i] = selVars;

""" + source[end:]
    start = source.index("        evaluationOfWeights = KoalaBearExt5.add(")
    end = source.index("        uint256 finalValue =", start)
    source = source[:start] + """        for (uint256 i = 0; i < QuinticWhirFixedConfig.ROUND_COUNT; ++i) {
            evaluationOfWeights = KoalaBearExt5.add(
                evaluationOfWeights,
                WhirVerifierCore5._evaluateConstraintSelectRaw(
                    roundChallenges[i], roundEqPoints[i], roundSelVars[i], allRandomness
                )
            );
        }
""" + source[end:]
    contract = "WhirVerifier5_" + label
    relative = "../src/whir/terminal_schedule_" + label + "/" + contract + ".sol"
    generated = root / "src/whir" / ("terminal_schedule_" + label)
    generated.mkdir(parents=True, exist_ok=False)
    (generated / (contract + ".sol")).write_text(source)
    (root / "src/generated" / (library + ".sol")).write_text(config)
    fixture_target = root / "testdata/terminal_schedules" / label
    shutil.copytree(args.fixture, fixture_target)
    fixture_path = "testdata/terminal_schedules/" + label
    harness = f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import {{Test}} from "forge-std/Test.sol";
import {{WhirStructs}} from "../src/whir/WhirStructs.sol";
import {{{contract}}} from "{relative}";
contract TerminalSchedule_{label}Test is Test {{
    {contract} private verifier;
    function setUp() public {{ verifier = new {contract}(); }}
    function load(string memory file) private view returns (WhirStructs.WhirProof memory) {{
        return abi.decode(vm.readFileBinary(string.concat("{fixture_path}/", file)), (WhirStructs.WhirProof));
    }}
    function statement() private view returns (WhirStructs.WhirStatement memory) {{
        return abi.decode(vm.readFileBinary("{fixture_path}/success_statement.abi"), (WhirStructs.WhirStatement));
    }}
    function testVerifySchedule() external view {{
        WhirStructs.WhirProof memory p = load("success_proof.abi");
        assertTrue(verifier.verify(p.initialCommitment, statement(), p));
    }}
    function testRejectBadCommitment() external {{ checkBad("bad_commitment_proof.abi"); }}
    function testRejectBadOod() external {{ checkBad("bad_ood_proof.abi"); }}
    function testRejectBadStir() external {{ checkBad("bad_stir_proof.abi"); }}
    function checkBad(string memory file) private {{
        bytes32 root = load("success_proof.abi").initialCommitment;
        WhirStructs.WhirProof memory p = load(file);
        WhirStructs.WhirStatement memory s = statement();
        vm.expectRevert();
        verifier.verify(root, s, p);
    }}
    function testRejectChangedStatement() external {{
        WhirStructs.WhirProof memory p = load("success_proof.abi");
        WhirStructs.WhirStatement memory s = statement();
        s.evaluations[0] = 0;
        vm.expectRevert();
        verifier.verify(p.initialCommitment, s, p);
    }}
}}
'''
    (root / "test" / ("TerminalSchedule_" + label + ".t.sol")).write_text(harness)
    script = f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import {{Script}} from "forge-std/Script.sol";
import {{WhirStructs}} from "../src/whir/WhirStructs.sol";
import {{{contract}}} from "{relative}";
contract WhirTxBenchmark_{label} is Script {{
    function run() external {{
        WhirStructs.WhirProof memory p = abi.decode(vm.readFileBinary("{fixture_path}/success_proof.abi"), (WhirStructs.WhirProof));
        WhirStructs.WhirStatement memory s = abi.decode(vm.readFileBinary("{fixture_path}/success_statement.abi"), (WhirStructs.WhirStatement));
        uint256 key = vm.envOr("PRIVATE_KEY", uint256(0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80));
        vm.startBroadcast(key);
        {contract} verifier = new {contract}();
        require(verifier.verify(p.initialCommitment, s, p), "VERIFY_FAILED");
        vm.stopBroadcast();
    }}
}}
'''
    (root / "script" / ("WhirTxBenchmark_" + label + ".s.sol")).write_text(script)
    print(label)


if __name__ == "__main__":
    main()
