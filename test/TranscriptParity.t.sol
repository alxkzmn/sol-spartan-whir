// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {KeccakChallenger} from "../src/transcript/KeccakChallenger.sol";
import {SpartanTranscript} from "../src/transcript/SpartanTranscript.sol";

contract TranscriptParityTest is Test {
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

    struct SpartanContextFixture {
        uint256 numCons;
        uint256 numVars;
        uint256 numIo;
        uint32 securityLevelBits;
        uint32 merkleSecurityBits;
        uint8 soundnessAssumption;
        uint32 powBits;
        uint256 foldingFactor;
        uint256 startingLogInvRate;
        uint256 rsDomainInitialReductionFactor;
        uint256[] publicInputs;
        bytes preimage;
        bytes32 digest;
        uint256[] checkpoint;
    }

    function testObserveBaseMatchesRawLittleEndianBytes() external pure {
        KeccakChallenger.State memory lhs;
        KeccakChallenger.State memory rhs;

        lhs.observeBase(0x01020304);
        rhs.observeBytes(hex"cce9f731");

        assertEq(keccak256(lhs.inputBuffer), keccak256(rhs.inputBuffer));
        assertEq(lhs.outputIndex, rhs.outputIndex);
    }

    function testObserveHashU8DigestMatchesRawDigestBytes() external pure {
        bytes32 digest =
            hex"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

        KeccakChallenger.State memory lhs;
        KeccakChallenger.State memory rhs;

        lhs.observeHashU8Digest(digest);
        rhs.observeBytes(abi.encodePacked(digest));

        assertEq(keccak256(lhs.inputBuffer), keccak256(rhs.inputBuffer));
        assertEq(lhs.outputIndex, rhs.outputIndex);
    }

    function testObserveHashU64DigestMatchesLittleEndianWords() external pure {
        bytes32 digest =
            hex"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

        KeccakChallenger.State memory lhs;
        KeccakChallenger.State memory rhs;

        lhs.observeHashU64Digest(digest);
        rhs.observeBytes(
            hex"07060504030201000f0e0d0c0b0a090817161514131211101f1e1d1c1b1a1918"
        );

        assertEq(keccak256(lhs.inputBuffer), keccak256(rhs.inputBuffer));
        assertEq(lhs.outputIndex, rhs.outputIndex);
    }

    function testReplayProverTranscriptTrace() external view {
        TranscriptTrace memory trace = _loadTrace();
        KeccakChallenger.State memory challenger = _replay(trace.proverEvents);
        _assertCheckpoint(challenger, trace.checkpointProver);
    }

    function testReplayVerifierTranscriptTrace() external view {
        TranscriptTrace memory trace = _loadTrace();
        KeccakChallenger.State memory challenger = _replay(trace.verifierEvents);
        _assertCheckpoint(challenger, trace.checkpointVerifier);
    }

    function testReplayTranscriptCheckpointParity() external view {
        TranscriptTrace memory trace = _loadTrace();
        KeccakChallenger.State memory prover = _replay(trace.proverEvents);
        KeccakChallenger.State memory verifier = _replay(trace.verifierEvents);

        uint256[4] memory proverCheckpoint = prover.sampleExt4Coeffs();
        uint256[4] memory verifierCheckpoint = verifier.sampleExt4Coeffs();

        assertTrue(trace.checkpointMatch);
        unchecked {
            for (uint256 i = 0; i < 4; ++i) {
                assertEq(proverCheckpoint[i], trace.checkpointProver[i]);
                assertEq(verifierCheckpoint[i], trace.checkpointVerifier[i]);
                assertEq(proverCheckpoint[i], verifierCheckpoint[i]);
            }
        }
    }

    function testReplaySpartanTranscriptContext() external view {
        SpartanContextFixture memory fixture = _loadSpartanContextFixture();
        SpartanTranscript.DomainSeparator memory domainSeparator = SpartanTranscript
            .DomainSeparator({
                numCons: fixture.numCons,
                numVars: fixture.numVars,
                numIo: fixture.numIo,
                securityLevelBits: fixture.securityLevelBits,
                merkleSecurityBits: fixture.merkleSecurityBits,
                soundnessAssumption: fixture.soundnessAssumption,
                powBits: fixture.powBits,
                foldingFactor: fixture.foldingFactor,
                startingLogInvRate: fixture.startingLogInvRate,
                rsDomainInitialReductionFactor: fixture.rsDomainInitialReductionFactor
            });

        bytes memory preimage = SpartanTranscript.domainSeparatorPreimage(
            domainSeparator
        );
        assertEq(preimage.length, 76);
        assertEq(keccak256(preimage), keccak256(fixture.preimage));

        bytes32 digest = SpartanTranscript.domainSeparatorDigest(domainSeparator);
        assertEq(digest, fixture.digest);

        KeccakChallenger.State memory challenger;
        bytes32 observedDigest;
        (challenger, observedDigest) = SpartanTranscript.observeSpartanContext(
            challenger,
            domainSeparator,
            fixture.publicInputs
        );
        assertEq(observedDigest, fixture.digest);
        _assertCheckpoint(challenger, fixture.checkpoint);
    }

    function _loadTrace() internal view returns (TranscriptTrace memory) {
        bytes memory raw = vm.readFileBinary(
            string.concat(TESTDATA, "transcript_trace_quartic.abi")
        );
        return abi.decode(raw, (TranscriptTrace));
    }

    function _loadSpartanContextFixture()
        internal
        view
        returns (SpartanContextFixture memory)
    {
        bytes memory raw = vm.readFileBinary(
            string.concat(TESTDATA, "spartan_transcript_context_quartic.abi")
        );
        return abi.decode(raw, (SpartanContextFixture));
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
        uint256[4] memory checkpoint = challenger.sampleExt4Coeffs();
        assertEq(expected.length, 4);

        unchecked {
            for (uint256 i = 0; i < 4; ++i) {
                assertEq(checkpoint[i], expected[i]);
            }
        }
    }
}
