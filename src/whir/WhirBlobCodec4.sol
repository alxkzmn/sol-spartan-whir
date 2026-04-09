// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {WhirStructs} from "./WhirStructs.sol";

library WhirBlobCodec4 {
    uint32 internal constant MAGIC = 0x57485242; // WHRB
    uint16 internal constant VERSION = 1;
    uint8 internal constant EFFECTIVE_DIGEST_BYTES = 20;
    uint8 internal constant EXTENSION_DEGREE = 4;
    uint8 internal constant ROUND_COUNT = 2;
    uint8 internal constant FLAGS = 0x03;

    uint256 internal constant HEADER_BYTES = 16;
    uint256 internal constant STATEMENT_POINT_ARITY = 16;
    uint256 internal constant STATEMENT_EVALUATIONS = 1;
    uint256 internal constant INITIAL_OOD_SAMPLES = 2;
    uint256 internal constant ROUND_OOD_SAMPLES = 2;
    uint256 internal constant INITIAL_SUMCHECK_EVALS = 8;
    uint256 internal constant ROUND_SUMCHECK_EVALS = 8;
    uint256 internal constant FINAL_SUMCHECK_EVALS = 8;
    uint256 internal constant ROUND0_NUM_QUERIES = 9;
    uint256 internal constant ROUND1_NUM_QUERIES = 6;
    uint256 internal constant FINAL_NUM_QUERIES = 5;
    uint256 internal constant ROW_LEN = 16;
    uint256 internal constant ROUND1_SUMCHECK_POW_WITNESSES = 4;
    uint256 internal constant FINAL_POLY_LEN = 16;

    uint256 private constant DIGEST_MASK = type(uint256).max << 96;
    uint256 private constant EXT4_MASK = type(uint256).max << 128;

    error BlobTooShort();
    error BlobMagicMismatch();
    error BlobVersionMismatch();
    error BlobDigestWidthMismatch();
    error BlobExtensionDegreeMismatch();
    error BlobRoundCountMismatch();
    error BlobFlagsMismatch();
    error BlobLengthMismatch();
    error BlobTrailingBytes();

    function decode(
        bytes calldata blob
    )
        internal
        pure
        returns (
            WhirStructs.WhirStatement memory statement,
            WhirStructs.WhirProof memory proof
        )
    {
        (
            uint256 round0DecommLen,
            uint256 round1DecommLen,
            uint256 finalDecommLen
        ) = validateHeader(blob);

        uint256 offset = HEADER_BYTES;

        statement.points = new uint256[][](1);
        statement.points[0] = new uint256[](STATEMENT_POINT_ARITY);
        for (uint256 i = 0; i < STATEMENT_POINT_ARITY; ++i) {
            (statement.points[0][i], offset) = readExt4(blob, offset);
        }
        statement.evaluations = new uint256[](STATEMENT_EVALUATIONS);
        (statement.evaluations[0], offset) = readExt4(blob, offset);

        (proof.initialCommitment, offset) = readDigest20(blob, offset);
        proof.initialOodAnswers = new uint256[](INITIAL_OOD_SAMPLES);
        for (uint256 i = 0; i < INITIAL_OOD_SAMPLES; ++i) {
            (proof.initialOodAnswers[i], offset) = readExt4(blob, offset);
        }
        proof.initialSumcheck.polynomialEvals = new uint256[](
            INITIAL_SUMCHECK_EVALS
        );
        for (uint256 i = 0; i < INITIAL_SUMCHECK_EVALS; ++i) {
            (proof.initialSumcheck.polynomialEvals[i], offset) = readExt4(
                blob,
                offset
            );
        }
        proof.initialSumcheck.powWitnesses = new uint256[](0);

        proof.rounds = new WhirStructs.WhirRoundProof[](ROUND_COUNT);
        offset = _decodeRound0(blob, offset, round0DecommLen, proof.rounds[0]);
        offset = _decodeRound1(blob, offset, round1DecommLen, proof.rounds[1]);

        proof.finalPoly = new uint256[](FINAL_POLY_LEN);
        for (uint256 i = 0; i < FINAL_POLY_LEN; ++i) {
            (proof.finalPoly[i], offset) = readExt4(blob, offset);
        }
        (proof.finalPowWitness, offset) = readBase(blob, offset);

        proof.finalQueryBatchPresent = true;
        proof.finalQueryBatch.kind = 1;
        proof.finalQueryBatch.numQueries = FINAL_NUM_QUERIES;
        proof.finalQueryBatch.rowLen = ROW_LEN;
        proof.finalQueryBatch.values = new uint256[](
            FINAL_NUM_QUERIES * ROW_LEN
        );
        for (uint256 i = 0; i < FINAL_NUM_QUERIES * ROW_LEN; ++i) {
            (proof.finalQueryBatch.values[i], offset) = readExt4(blob, offset);
        }
        proof.finalQueryBatch.decommitments = new bytes32[](finalDecommLen);
        for (uint256 i = 0; i < finalDecommLen; ++i) {
            (proof.finalQueryBatch.decommitments[i], offset) = readDigest20(
                blob,
                offset
            );
        }

        proof.finalSumcheckPresent = true;
        proof.finalSumcheck.polynomialEvals = new uint256[](
            FINAL_SUMCHECK_EVALS
        );
        for (uint256 i = 0; i < FINAL_SUMCHECK_EVALS; ++i) {
            (proof.finalSumcheck.polynomialEvals[i], offset) = readExt4(
                blob,
                offset
            );
        }
        proof.finalSumcheck.powWitnesses = new uint256[](0);

        if (offset != blob.length) {
            revert BlobTrailingBytes();
        }
    }

    function _decodeRound0(
        bytes calldata blob,
        uint256 offset,
        uint256 decommLen,
        WhirStructs.WhirRoundProof memory round
    ) private pure returns (uint256) {
        (round.commitment, offset) = readDigest20(blob, offset);
        round.oodAnswers = new uint256[](ROUND_OOD_SAMPLES);
        for (uint256 i = 0; i < ROUND_OOD_SAMPLES; ++i) {
            (round.oodAnswers[i], offset) = readExt4(blob, offset);
        }
        (round.powWitness, offset) = readBase(blob, offset);

        round.queryBatch.kind = 0;
        round.queryBatch.numQueries = ROUND0_NUM_QUERIES;
        round.queryBatch.rowLen = ROW_LEN;
        round.queryBatch.values = new uint256[](ROUND0_NUM_QUERIES * ROW_LEN);
        for (uint256 i = 0; i < ROUND0_NUM_QUERIES * ROW_LEN; ++i) {
            (round.queryBatch.values[i], offset) = readBase(blob, offset);
        }
        round.queryBatch.decommitments = new bytes32[](decommLen);
        for (uint256 i = 0; i < decommLen; ++i) {
            (round.queryBatch.decommitments[i], offset) = readDigest20(
                blob,
                offset
            );
        }

        round.sumcheck.polynomialEvals = new uint256[](ROUND_SUMCHECK_EVALS);
        for (uint256 i = 0; i < ROUND_SUMCHECK_EVALS; ++i) {
            (round.sumcheck.polynomialEvals[i], offset) = readExt4(
                blob,
                offset
            );
        }
        round.sumcheck.powWitnesses = new uint256[](0);
        return offset;
    }

    function _decodeRound1(
        bytes calldata blob,
        uint256 offset,
        uint256 decommLen,
        WhirStructs.WhirRoundProof memory round
    ) private pure returns (uint256) {
        (round.commitment, offset) = readDigest20(blob, offset);
        round.oodAnswers = new uint256[](ROUND_OOD_SAMPLES);
        for (uint256 i = 0; i < ROUND_OOD_SAMPLES; ++i) {
            (round.oodAnswers[i], offset) = readExt4(blob, offset);
        }
        (round.powWitness, offset) = readBase(blob, offset);

        round.queryBatch.kind = 1;
        round.queryBatch.numQueries = ROUND1_NUM_QUERIES;
        round.queryBatch.rowLen = ROW_LEN;
        round.queryBatch.values = new uint256[](ROUND1_NUM_QUERIES * ROW_LEN);
        for (uint256 i = 0; i < ROUND1_NUM_QUERIES * ROW_LEN; ++i) {
            (round.queryBatch.values[i], offset) = readExt4(blob, offset);
        }
        round.queryBatch.decommitments = new bytes32[](decommLen);
        for (uint256 i = 0; i < decommLen; ++i) {
            (round.queryBatch.decommitments[i], offset) = readDigest20(
                blob,
                offset
            );
        }

        round.sumcheck.polynomialEvals = new uint256[](ROUND_SUMCHECK_EVALS);
        for (uint256 i = 0; i < ROUND_SUMCHECK_EVALS; ++i) {
            (round.sumcheck.polynomialEvals[i], offset) = readExt4(
                blob,
                offset
            );
        }
        round.sumcheck.powWitnesses = new uint256[](
            ROUND1_SUMCHECK_POW_WITNESSES
        );
        for (uint256 i = 0; i < ROUND1_SUMCHECK_POW_WITNESSES; ++i) {
            (round.sumcheck.powWitnesses[i], offset) = readBase(blob, offset);
        }
        return offset;
    }

    function validateHeader(
        bytes calldata blob
    )
        internal
        pure
        returns (
            uint256 round0DecommLen,
            uint256 round1DecommLen,
            uint256 finalDecommLen
        )
    {
        if (blob.length < HEADER_BYTES) {
            revert BlobTooShort();
        }

        assembly ("memory-safe") {
            let base := blob.offset
            round0DecommLen := shr(240, calldataload(add(base, 10)))
            round1DecommLen := shr(240, calldataload(add(base, 12)))
            finalDecommLen := shr(240, calldataload(add(base, 14)))
        }

        if (readU32(blob, 0) != MAGIC) {
            revert BlobMagicMismatch();
        }
        if (readU16(blob, 4) != VERSION) {
            revert BlobVersionMismatch();
        }
        if (readU8(blob, 6) != EFFECTIVE_DIGEST_BYTES) {
            revert BlobDigestWidthMismatch();
        }
        if (readU8(blob, 7) != EXTENSION_DEGREE) {
            revert BlobExtensionDegreeMismatch();
        }
        if (readU8(blob, 8) != ROUND_COUNT) {
            revert BlobRoundCountMismatch();
        }
        if (readU8(blob, 9) != FLAGS) {
            revert BlobFlagsMismatch();
        }

        uint256 expectedLen = expectedLength(
            round0DecommLen,
            round1DecommLen,
            finalDecommLen
        );
        if (blob.length != expectedLen) {
            revert BlobLengthMismatch();
        }
    }

    function expectedLength(
        uint256 round0DecommLen,
        uint256 round1DecommLen,
        uint256 finalDecommLen
    ) internal pure returns (uint256) {
        return
            HEADER_BYTES +
            STATEMENT_POINT_ARITY *
            16 +
            STATEMENT_EVALUATIONS *
            16 +
            EFFECTIVE_DIGEST_BYTES +
            INITIAL_OOD_SAMPLES *
            16 +
            INITIAL_SUMCHECK_EVALS *
            16 +
            EFFECTIVE_DIGEST_BYTES +
            ROUND_OOD_SAMPLES *
            16 +
            4 +
            ROUND0_NUM_QUERIES *
            ROW_LEN *
            4 +
            round0DecommLen *
            EFFECTIVE_DIGEST_BYTES +
            ROUND_SUMCHECK_EVALS *
            16 +
            EFFECTIVE_DIGEST_BYTES +
            ROUND_OOD_SAMPLES *
            16 +
            4 +
            ROUND1_NUM_QUERIES *
            ROW_LEN *
            16 +
            round1DecommLen *
            EFFECTIVE_DIGEST_BYTES +
            ROUND_SUMCHECK_EVALS *
            16 +
            ROUND1_SUMCHECK_POW_WITNESSES *
            4 +
            FINAL_POLY_LEN *
            16 +
            4 +
            FINAL_NUM_QUERIES *
            ROW_LEN *
            16 +
            finalDecommLen *
            EFFECTIVE_DIGEST_BYTES +
            FINAL_SUMCHECK_EVALS *
            16;
    }

    function readDigest20(
        bytes calldata blob,
        uint256 offset
    ) internal pure returns (bytes32 value, uint256 next) {
        uint256 word;
        assembly ("memory-safe") {
            word := calldataload(add(blob.offset, offset))
        }
        value = bytes32(word & DIGEST_MASK);
        next = offset + EFFECTIVE_DIGEST_BYTES;
    }

    function readExt4(
        bytes calldata blob,
        uint256 offset
    ) internal pure returns (uint256 value, uint256 next) {
        uint256 word;
        assembly ("memory-safe") {
            word := calldataload(add(blob.offset, offset))
        }
        value = word & EXT4_MASK;
        next = offset + 16;
    }

    function readBase(
        bytes calldata blob,
        uint256 offset
    ) internal pure returns (uint256 value, uint256 next) {
        assembly ("memory-safe") {
            value := shr(224, calldataload(add(blob.offset, offset)))
        }
        next = offset + 4;
    }

    function readU32(
        bytes calldata blob,
        uint256 offset
    ) internal pure returns (uint32 value) {
        assembly ("memory-safe") {
            value := shr(224, calldataload(add(blob.offset, offset)))
        }
    }

    function readU16(
        bytes calldata blob,
        uint256 offset
    ) internal pure returns (uint16 value) {
        assembly ("memory-safe") {
            value := shr(240, calldataload(add(blob.offset, offset)))
        }
    }

    function readU8(
        bytes calldata blob,
        uint256 offset
    ) internal pure returns (uint8 value) {
        assembly ("memory-safe") {
            value := shr(248, calldataload(add(blob.offset, offset)))
        }
    }
}
