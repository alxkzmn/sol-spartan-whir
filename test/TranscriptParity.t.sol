// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {KeccakChallenger} from "../src/transcript/KeccakChallenger.sol";
import {SpartanTranscript} from "../src/transcript/SpartanTranscript.sol";
import {WhirTranscript} from "../src/transcript/WhirTranscript.sol";
import {WhirStructs} from "../src/whir/WhirStructs.sol";

contract TranscriptParityTest is Test {
    using KeccakChallenger for KeccakChallenger.State;
    using WhirTranscript for KeccakChallenger.State;

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
        bytes32 digest = hex"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

        KeccakChallenger.State memory lhs;
        KeccakChallenger.State memory rhs;

        lhs.observeHashU8Digest(digest);
        rhs.observeBytes(abi.encodePacked(digest));

        assertEq(keccak256(lhs.inputBuffer), keccak256(rhs.inputBuffer));
        assertEq(lhs.outputIndex, rhs.outputIndex);
    }

    function testObserveHashU64DigestMatchesLittleEndianWords() external pure {
        bytes32 digest = hex"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

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
        KeccakChallenger.State memory challenger = _replay(
            trace.verifierEvents
        );
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

    function testReplayVerifierWhirTranscriptSemantically() external view {
        TranscriptTrace memory trace = _loadTrace();
        WhirStructs.WhirProof memory proof = _loadWhirProof();

        KeccakChallenger.State memory challenger;
        uint256 fsPatternLen = 0;
        while (
            fsPatternLen < trace.verifierEvents.length &&
            trace.verifierEvents[fsPatternLen].op == OP_OBSERVE_BYTES &&
            trace.verifierEvents[fsPatternLen].observedBytes.length == 4
        ) {
            unchecked {
                ++fsPatternLen;
            }
        }
        uint256[] memory fsPattern = new uint256[](fsPatternLen);
        unchecked {
            for (uint256 i = 0; i < fsPatternLen; ++i) {
                fsPattern[i] = trace.verifierEvents[i].arg0;
            }
        }

        challenger.observeWhirFsPattern(fsPattern);

        uint256 cursor = fsPatternLen;

        challenger.observeHashU64Digest(proof.initialCommitment);
        cursor += 1;

        cursor = _consumeSampleEventsUntilObserve(
            challenger,
            trace.verifierEvents,
            cursor
        );

        challenger.observeExt4Slice(proof.initialOodAnswers);
        cursor += proof.initialOodAnswers.length * 4;

        cursor = _consumeSampleEventsUntilObserve(
            challenger,
            trace.verifierEvents,
            cursor
        );

        cursor = _replaySumcheckSemantically(
            challenger,
            trace.verifierEvents,
            cursor,
            proof.initialSumcheck
        );

        unchecked {
            for (uint256 i = 0; i < proof.rounds.length; ++i) {
                WhirStructs.WhirRoundProof memory round = proof.rounds[i];

                challenger.observeHashU64Digest(round.commitment);
                cursor += 1;

                cursor = _consumeSampleEventsUntilObserve(
                    challenger,
                    trace.verifierEvents,
                    cursor
                );

                challenger.observeExt4Slice(round.oodAnswers);
                cursor += round.oodAnswers.length * 4;

                cursor = _consumeSampleEventsUntilObserve(
                    challenger,
                    trace.verifierEvents,
                    cursor
                );

                cursor = _replaySumcheckSemantically(
                    challenger,
                    trace.verifierEvents,
                    cursor,
                    round.sumcheck
                );
            }
        }

        challenger.observeExt4Slice(proof.finalPoly);
        cursor += proof.finalPoly.length * 4;

        cursor = _consumeSampleEventsUntilObserve(
            challenger,
            trace.verifierEvents,
            cursor
        );

        if (proof.finalSumcheckPresent) {
            cursor = _replaySumcheckSemantically(
                challenger,
                trace.verifierEvents,
                cursor,
                proof.finalSumcheck
            );
        }

        assertEq(cursor, trace.verifierEvents.length);
        _assertSameState(challenger, _replay(trace.verifierEvents));
        _assertCheckpoint(challenger, trace.checkpointVerifier);
    }

    function testReplaySpartanTranscriptContext() external view {
        SpartanContextFixture memory fixture = _loadSpartanContextFixture();
        SpartanTranscript.DomainSeparator
            memory domainSeparator = SpartanTranscript.DomainSeparator({
                numCons: fixture.numCons,
                numVars: fixture.numVars,
                numIo: fixture.numIo,
                securityLevelBits: fixture.securityLevelBits,
                merkleSecurityBits: fixture.merkleSecurityBits,
                soundnessAssumption: fixture.soundnessAssumption,
                powBits: fixture.powBits,
                foldingFactor: fixture.foldingFactor,
                startingLogInvRate: fixture.startingLogInvRate,
                rsDomainInitialReductionFactor: fixture
                    .rsDomainInitialReductionFactor
            });

        bytes memory preimage = SpartanTranscript.domainSeparatorPreimage(
            domainSeparator
        );
        assertEq(preimage.length, 76);
        assertEq(keccak256(preimage), keccak256(fixture.preimage));

        bytes32 digest = SpartanTranscript.domainSeparatorDigest(
            domainSeparator
        );
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

    function _loadWhirProof()
        internal
        view
        returns (WhirStructs.WhirProof memory)
    {
        bytes memory raw = vm.readFileBinary(
            string.concat(TESTDATA, "quartic_whir_success_proof.abi")
        );
        return abi.decode(raw, (WhirStructs.WhirProof));
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

    function _replay(
        TranscriptEvent[] memory events
    ) internal pure returns (KeccakChallenger.State memory challenger) {
        unchecked {
            for (uint256 i = 0; i < events.length; ++i) {
                TranscriptEvent memory traceEvent = events[i];
                if (traceEvent.op == OP_OBSERVE_BYTES) {
                    challenger.observeBytes(traceEvent.observedBytes);
                } else if (traceEvent.op == OP_SAMPLE_BASE) {
                    assertEq(challenger.sampleBase(), traceEvent.arg0);
                } else if (traceEvent.op == OP_SAMPLE_BITS) {
                    assertEq(
                        challenger.sampleBits(traceEvent.arg0),
                        traceEvent.arg1
                    );
                } else if (traceEvent.op == OP_GRIND) {
                    assertTrue(
                        challenger.checkWitness(
                            traceEvent.arg0,
                            traceEvent.arg1
                        )
                    );
                } else {
                    revert("BAD_TRANSCRIPT_OP");
                }
            }
        }
    }

    function _replaySumcheckSemantically(
        KeccakChallenger.State memory challenger,
        TranscriptEvent[] memory events,
        uint256 cursor,
        WhirStructs.SumcheckData memory sumcheck
    ) internal pure returns (uint256) {
        assertEq(sumcheck.polynomialEvals.length % 2, 0);

        unchecked {
            for (uint256 i = 0; i < sumcheck.polynomialEvals.length; i += 2) {
                challenger.observeSumcheckRoundPolyExt4(
                    sumcheck.polynomialEvals[i],
                    sumcheck.polynomialEvals[i + 1]
                );
                cursor += 8;
                cursor = _consumeSampleEventsUntilObserve(
                    challenger,
                    events,
                    cursor
                );
            }
        }

        return cursor;
    }

    function _consumeSampleEventsUntilObserve(
        KeccakChallenger.State memory challenger,
        TranscriptEvent[] memory events,
        uint256 cursor
    ) internal pure returns (uint256) {
        while (
            cursor < events.length && events[cursor].op != OP_OBSERVE_BYTES
        ) {
            if (events[cursor].op == OP_SAMPLE_BASE) {
                assertEq(challenger.sampleBase(), events[cursor].arg0);
                unchecked {
                    ++cursor;
                }
            } else if (events[cursor].op == OP_SAMPLE_BITS) {
                cursor = _assertNextSampleBits(
                    challenger,
                    events,
                    cursor,
                    events[cursor].arg0
                );
            } else if (events[cursor].op == OP_GRIND) {
                assertTrue(
                    challenger.checkWitness(
                        events[cursor].arg0,
                        events[cursor].arg1
                    )
                );
                unchecked {
                    ++cursor;
                }
            } else {
                revert("BAD_TRANSCRIPT_OP");
            }
        }

        return cursor;
    }

    function _assertNextSampleBits(
        KeccakChallenger.State memory challenger,
        TranscriptEvent[] memory events,
        uint256 cursor,
        uint256 bits
    ) internal pure returns (uint256) {
        assertLt(cursor, events.length);
        assertEq(events[cursor].op, OP_SAMPLE_BITS);
        assertEq(events[cursor].arg0, bits);
        assertEq(challenger.sampleBits(bits), events[cursor].arg1);
        return cursor + 1;
    }

    function _assertCheckpoint(
        KeccakChallenger.State memory challenger,
        uint256[] memory expected
    ) internal pure {
        uint256[4] memory checkpoint = challenger.sampleExt4Coeffs();
        assertEq(expected.length, 4);

        unchecked {
            for (uint256 i = 0; i < 4; ++i) {
                assertEq(checkpoint[i], expected[i]);
            }
        }
    }

    function _assertSameState(
        KeccakChallenger.State memory lhs,
        KeccakChallenger.State memory rhs
    ) internal pure {
        assertEq(keccak256(lhs.inputBuffer), keccak256(rhs.inputBuffer));
        assertEq(keccak256(lhs.outputBuffer), keccak256(rhs.outputBuffer));
        assertEq(lhs.outputIndex, rhs.outputIndex);
    }
}
