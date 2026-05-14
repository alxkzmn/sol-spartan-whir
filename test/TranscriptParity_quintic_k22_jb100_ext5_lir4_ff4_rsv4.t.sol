// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { KeccakChallenger } from "../src/transcript/KeccakChallenger.sol";

contract TranscriptParityQuinticK22Jb100Ext5Test is Test {
    using KeccakChallenger for KeccakChallenger.State;

    uint8 internal constant OP_OBSERVE_BYTES = 0;
    uint8 internal constant OP_SAMPLE_BASE = 1;
    uint8 internal constant OP_SAMPLE_BITS = 2;
    uint8 internal constant OP_GRIND = 3;
    string internal constant TESTDATA = "testdata/";

    struct TranscriptEvent {
        uint8 op;
        bytes observedBytes;
        uint256 arg0;
        uint256 arg1;
    }

    struct TranscriptTrace {
        TranscriptEvent[] proverEvents;
        TranscriptEvent[] verifierEvents;
        uint256[] checkpointProver;
        uint256[] checkpointVerifier;
        bool checkpointMatch;
    }

    function testReplayProverTranscriptTraceQuintic() external view {
        TranscriptTrace memory trace = _loadTrace();
        KeccakChallenger.State memory challenger = _replay(trace.proverEvents);
        _assertCheckpoint(challenger, trace.checkpointProver);
    }

    function testReplayVerifierTranscriptTraceQuintic() external view {
        TranscriptTrace memory trace = _loadTrace();
        KeccakChallenger.State memory challenger = _replay(trace.verifierEvents);
        _assertCheckpoint(challenger, trace.checkpointVerifier);
    }

    function testReplayTranscriptCheckpointParityQuintic() external view {
        TranscriptTrace memory trace = _loadTrace();
        KeccakChallenger.State memory prover = _replay(trace.proverEvents);
        KeccakChallenger.State memory verifier = _replay(trace.verifierEvents);

        uint256[5] memory proverCheckpoint = prover.sampleExt5Coeffs();
        uint256[5] memory verifierCheckpoint = verifier.sampleExt5Coeffs();

        assertTrue(trace.checkpointMatch);
        unchecked {
            for (uint256 i = 0; i < 5; ++i) {
                assertEq(proverCheckpoint[i], trace.checkpointProver[i]);
                assertEq(verifierCheckpoint[i], trace.checkpointVerifier[i]);
                assertEq(proverCheckpoint[i], verifierCheckpoint[i]);
            }
        }
    }

    function _loadTrace() internal view returns (TranscriptTrace memory) {
        bytes memory raw = vm.readFileBinary(
            string.concat(TESTDATA, "transcript_trace_quintic_k22_jb100_ext5_lir4_ff4_rsv4.abi")
        );
        return abi.decode(raw, (TranscriptTrace));
    }

    function _replay(TranscriptEvent[] memory events)
        internal
        pure
        returns (KeccakChallenger.State memory challenger)
    {
        unchecked {
            for (uint256 i = 0; i < events.length; ++i) {
                TranscriptEvent memory traceEvent = events[i];
                if (traceEvent.op == OP_OBSERVE_BYTES) {
                    challenger.observeBytes(traceEvent.observedBytes);
                } else if (traceEvent.op == OP_SAMPLE_BASE) {
                    assertEq(challenger.sampleBase(), traceEvent.arg0);
                } else if (traceEvent.op == OP_SAMPLE_BITS) {
                    assertEq(challenger.sampleBits(traceEvent.arg0), traceEvent.arg1);
                } else if (traceEvent.op == OP_GRIND) {
                    assertTrue(challenger.checkWitness(traceEvent.arg0, traceEvent.arg1));
                } else {
                    revert("BAD_TRANSCRIPT_OP");
                }
            }
        }
    }

    function _assertCheckpoint(KeccakChallenger.State memory challenger, uint256[] memory expected)
        internal
        pure
    {
        uint256[5] memory checkpoint = challenger.sampleExt5Coeffs();
        assertEq(expected.length, 5);
        unchecked {
            for (uint256 i = 0; i < 5; ++i) {
                assertEq(checkpoint[i], expected[i]);
            }
        }
    }
}
