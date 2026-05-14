// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { WhirStructs } from "../WhirStructs.sol";

library WhirBlobCodec5 {
    uint32 internal constant MAGIC = 0x57485242;
    uint16 internal constant VERSION = 1;
    uint8 internal constant EFFECTIVE_DIGEST_BYTES = 20;
    uint8 internal constant EXTENSION_DEGREE = 5;
    uint8 internal constant ROUND_COUNT = 3;
    uint8 internal constant FLAGS = 0x03;

    uint256 internal constant HEADER_BYTES = 18;
    uint256 internal constant STATEMENT_POINT_ARITY = 22;
    uint256 internal constant STATEMENT_EVALUATIONS = 1;
    uint256 internal constant INITIAL_OOD_SAMPLES = 1;
    uint256 internal constant ROUND_OOD_SAMPLES = 1;
    uint256 internal constant INITIAL_SUMCHECK_EVALS = 8;
    uint256 internal constant ROUND_SUMCHECK_EVALS = 8;
    uint256 internal constant FINAL_SUMCHECK_EVALS = 12;
    uint256 internal constant INITIAL_SUMCHECK_POW_WITNESSES = 4;
    uint256 internal constant ROUND_SUMCHECK_POW_WITNESSES = 4;
    uint256 internal constant ROUND0_NUM_QUERIES = 38;
    uint256 internal constant ROUND1_NUM_QUERIES = 31;
    uint256 internal constant ROUND2_NUM_QUERIES = 19;
    uint256 internal constant FINAL_NUM_QUERIES = 14;
    uint256 internal constant ROW_LEN = 16;
    uint256 internal constant FINAL_POLY_LEN = 64;

    uint256 private constant DIGEST_MASK = type(uint256).max << 96;

    error BlobTooShort();
    error BlobMagicMismatch();
    error BlobVersionMismatch();
    error BlobDigestWidthMismatch();
    error BlobExtensionDegreeMismatch();
    error BlobRoundCountMismatch();
    error BlobFlagsMismatch();
    error BlobLengthMismatch();
    error BlobTrailingBytes();

    function decode(bytes calldata blob)
        internal
        pure
        returns (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory proof)
    {
        (
            uint256 round0DecommLen,
            uint256 round1DecommLen,
            uint256 round2DecommLen,
            uint256 finalDecommLen
        ) = validateHeader(blob);

        uint256 offset = HEADER_BYTES;

        statement.points = new uint256[][](1);
        statement.points[0] = new uint256[](STATEMENT_POINT_ARITY);
        for (uint256 i = 0; i < STATEMENT_POINT_ARITY; ++i) {
            (statement.points[0][i], offset) = readExt5(blob, offset);
        }
        statement.evaluations = new uint256[](STATEMENT_EVALUATIONS);
        (statement.evaluations[0], offset) = readExt5(blob, offset);

        (proof.initialCommitment, offset) = readDigest20(blob, offset);
        proof.initialOodAnswers = new uint256[](INITIAL_OOD_SAMPLES);
        (proof.initialOodAnswers[0], offset) = readExt5Le(blob, offset);
        proof.initialSumcheck.polynomialEvals = new uint256[](INITIAL_SUMCHECK_EVALS);
        for (uint256 i = 0; i < INITIAL_SUMCHECK_EVALS; ++i) {
            (proof.initialSumcheck.polynomialEvals[i], offset) = readExt5Le(blob, offset);
        }
        proof.initialSumcheck.powWitnesses = new uint256[](INITIAL_SUMCHECK_POW_WITNESSES);
        for (uint256 i = 0; i < INITIAL_SUMCHECK_POW_WITNESSES; ++i) {
            (proof.initialSumcheck.powWitnesses[i], offset) = readBaseLe(blob, offset);
        }

        proof.rounds = new WhirStructs.WhirRoundProof[](ROUND_COUNT);
        offset =
            _decodeRound(blob, offset, round0DecommLen, proof.rounds[0], true, ROUND0_NUM_QUERIES);
        offset =
            _decodeRound(blob, offset, round1DecommLen, proof.rounds[1], false, ROUND1_NUM_QUERIES);
        offset =
            _decodeRound(blob, offset, round2DecommLen, proof.rounds[2], false, ROUND2_NUM_QUERIES);

        proof.finalPoly = new uint256[](FINAL_POLY_LEN);
        for (uint256 i = 0; i < FINAL_POLY_LEN; ++i) {
            (proof.finalPoly[i], offset) = readExt5(blob, offset);
        }
        (proof.finalPowWitness, offset) = readBaseLe(blob, offset);

        proof.finalQueryBatchPresent = true;
        proof.finalQueryBatch.kind = 1;
        proof.finalQueryBatch.numQueries = FINAL_NUM_QUERIES;
        proof.finalQueryBatch.rowLen = ROW_LEN;
        proof.finalQueryBatch.values = new uint256[](FINAL_NUM_QUERIES * ROW_LEN);
        for (uint256 i = 0; i < FINAL_NUM_QUERIES * ROW_LEN; ++i) {
            (proof.finalQueryBatch.values[i], offset) = readExt5(blob, offset);
        }
        proof.finalQueryBatch.decommitments = new bytes32[](finalDecommLen);
        for (uint256 i = 0; i < finalDecommLen; ++i) {
            (proof.finalQueryBatch.decommitments[i], offset) = readDigest20(blob, offset);
        }

        proof.finalSumcheckPresent = true;
        proof.finalSumcheck.polynomialEvals = new uint256[](FINAL_SUMCHECK_EVALS);
        for (uint256 i = 0; i < FINAL_SUMCHECK_EVALS; ++i) {
            (proof.finalSumcheck.polynomialEvals[i], offset) = readExt5Le(blob, offset);
        }
        proof.finalSumcheck.powWitnesses = new uint256[](0);

        if (offset != blob.length) {
            revert BlobTrailingBytes();
        }
    }

    function _decodeRound(
        bytes calldata blob,
        uint256 offset,
        uint256 decommLen,
        WhirStructs.WhirRoundProof memory round,
        bool isBase,
        uint256 numQueries
    ) private pure returns (uint256) {
        (round.commitment, offset) = readDigest20(blob, offset);
        round.oodAnswers = new uint256[](ROUND_OOD_SAMPLES);
        (round.oodAnswers[0], offset) = readExt5Le(blob, offset);
        (round.powWitness, offset) = readBaseLe(blob, offset);

        round.queryBatch.kind = isBase ? 0 : 1;
        round.queryBatch.numQueries = numQueries;
        round.queryBatch.rowLen = ROW_LEN;
        round.queryBatch.values = new uint256[](numQueries * ROW_LEN);
        for (uint256 i = 0; i < numQueries * ROW_LEN; ++i) {
            if (isBase) {
                (round.queryBatch.values[i], offset) = readBase(blob, offset);
            } else {
                (round.queryBatch.values[i], offset) = readExt5(blob, offset);
            }
        }
        round.queryBatch.decommitments = new bytes32[](decommLen);
        for (uint256 i = 0; i < decommLen; ++i) {
            (round.queryBatch.decommitments[i], offset) = readDigest20(blob, offset);
        }

        round.sumcheck.polynomialEvals = new uint256[](ROUND_SUMCHECK_EVALS);
        for (uint256 i = 0; i < ROUND_SUMCHECK_EVALS; ++i) {
            (round.sumcheck.polynomialEvals[i], offset) = readExt5Le(blob, offset);
        }
        round.sumcheck.powWitnesses = new uint256[](ROUND_SUMCHECK_POW_WITNESSES);
        for (uint256 i = 0; i < ROUND_SUMCHECK_POW_WITNESSES; ++i) {
            (round.sumcheck.powWitnesses[i], offset) = readBaseLe(blob, offset);
        }
        return offset;
    }

    function validateHeader(bytes calldata blob)
        internal
        pure
        returns (
            uint256 round0DecommLen,
            uint256 round1DecommLen,
            uint256 round2DecommLen,
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
            round2DecommLen := shr(240, calldataload(add(base, 14)))
            finalDecommLen := shr(240, calldataload(add(base, 16)))
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

        uint256 expectedLen =
            expectedLength(round0DecommLen, round1DecommLen, round2DecommLen, finalDecommLen);
        if (blob.length != expectedLen) {
            revert BlobLengthMismatch();
        }
    }

    function expectedLength(
        uint256 round0DecommLen,
        uint256 round1DecommLen,
        uint256 round2DecommLen,
        uint256 finalDecommLen
    ) internal pure returns (uint256) {
        return HEADER_BYTES + STATEMENT_POINT_ARITY * 20 + STATEMENT_EVALUATIONS * 20
            + EFFECTIVE_DIGEST_BYTES + INITIAL_OOD_SAMPLES * 20 + INITIAL_SUMCHECK_EVALS * 20
            + INITIAL_SUMCHECK_POW_WITNESSES * 4 + EFFECTIVE_DIGEST_BYTES + ROUND_OOD_SAMPLES * 20
            + 4 + ROUND0_NUM_QUERIES * ROW_LEN * 4 + round0DecommLen * EFFECTIVE_DIGEST_BYTES
            + ROUND_SUMCHECK_EVALS * 20 + ROUND_SUMCHECK_POW_WITNESSES * 4 + EFFECTIVE_DIGEST_BYTES
            + ROUND_OOD_SAMPLES * 20 + 4 + ROUND1_NUM_QUERIES * ROW_LEN * 20 + round1DecommLen
            * EFFECTIVE_DIGEST_BYTES + ROUND_SUMCHECK_EVALS * 20 + ROUND_SUMCHECK_POW_WITNESSES * 4
            + EFFECTIVE_DIGEST_BYTES + ROUND_OOD_SAMPLES * 20 + 4 + ROUND2_NUM_QUERIES * ROW_LEN
            * 20 + round2DecommLen * EFFECTIVE_DIGEST_BYTES + ROUND_SUMCHECK_EVALS * 20
            + ROUND_SUMCHECK_POW_WITNESSES * 4 + FINAL_POLY_LEN * 20 + 4 + FINAL_NUM_QUERIES
            * ROW_LEN * 20 + finalDecommLen * EFFECTIVE_DIGEST_BYTES + FINAL_SUMCHECK_EVALS * 20;
    }

    function readDigest20(bytes calldata blob, uint256 offset)
        internal
        pure
        returns (bytes32 value, uint256 next)
    {
        uint256 word;
        assembly ("memory-safe") {
            word := calldataload(add(blob.offset, offset))
        }
        value = bytes32(word & DIGEST_MASK);
        next = offset + EFFECTIVE_DIGEST_BYTES;
    }

    function readExt5(bytes calldata blob, uint256 offset)
        internal
        pure
        returns (uint256 value, uint256 next)
    {
        assembly ("memory-safe") {
            value := and(calldataload(add(blob.offset, offset)), not(sub(shl(96, 1), 1)))
        }
        next = offset + 20;
    }

    function readBase(bytes calldata blob, uint256 offset)
        internal
        pure
        returns (uint256 value, uint256 next)
    {
        assembly ("memory-safe") {
            value := shr(224, calldataload(add(blob.offset, offset)))
        }
        next = offset + 4;
    }

    function readBaseLe(bytes calldata blob, uint256 offset)
        internal
        pure
        returns (uint256 value, uint256 next)
    {
        uint32 littleEndian;
        assembly ("memory-safe") {
            littleEndian := shr(224, calldataload(add(blob.offset, offset)))
        }
        value = _bswap32(littleEndian);
        next = offset + 4;
    }

    function readExt5Le(bytes calldata blob, uint256 offset)
        internal
        pure
        returns (uint256 value, uint256 next)
    {
        uint256 word;
        assembly ("memory-safe") {
            word := calldataload(add(blob.offset, offset))
        }

        value = (_bswap32(uint32(word >> 224)) << 224) | (_bswap32(uint32(word >> 192)) << 192)
            | (_bswap32(uint32(word >> 160)) << 160) | (_bswap32(uint32(word >> 128)) << 128)
            | (_bswap32(uint32(word >> 96)) << 96);
        next = offset + 20;
    }

    function readU32(bytes calldata blob, uint256 offset) internal pure returns (uint32 value) {
        assembly ("memory-safe") {
            value := shr(224, calldataload(add(blob.offset, offset)))
        }
    }

    function readU16(bytes calldata blob, uint256 offset) internal pure returns (uint16 value) {
        assembly ("memory-safe") {
            value := shr(240, calldataload(add(blob.offset, offset)))
        }
    }

    function readU8(bytes calldata blob, uint256 offset) internal pure returns (uint8 value) {
        assembly ("memory-safe") {
            value := shr(248, calldataload(add(blob.offset, offset)))
        }
    }

    function _bswap32(uint32 x) private pure returns (uint256) {
        return ((uint256(x) & 0x000000ff) << 24) | ((uint256(x) & 0x0000ff00) << 8)
            | ((uint256(x) & 0x00ff0000) >> 8) | ((uint256(x) & 0xff000000) >> 24);
    }
}
