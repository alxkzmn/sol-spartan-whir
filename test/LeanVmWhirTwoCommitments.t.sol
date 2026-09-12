// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { KoalaBearExt5 as EF } from "../src/field/KoalaBearExt5.sol";
import { LeanVmTranscript as Transcript } from "../src/leanvm/LeanVmTranscript.sol";
import { LeanVmWhir as Whir } from "../src/leanvm/LeanVmWhir.sol";

contract LeanVmWhirTwoCommitmentsHarness {
    using Transcript for Transcript.State;

    function initialize(
        bytes calldata raw,
        uint256 batchingPowBits,
        Whir.Statement[] memory primaryStatements,
        Whir.Statement[] memory secondaryStatements
    )
        external
        pure
        returns (
            bytes32 primaryRoot,
            bytes32 secondaryRoot,
            uint256 target,
            uint256 polynomialRandomness,
            uint256 gamma,
            uint256 theta
        )
    {
        uint256[8] memory capacity;
        Transcript.State memory state = Transcript.initialize(capacity);
        Whir.Commitment memory primary = Whir.parseRoot(state, raw, 2);
        Whir.Commitment memory secondary = Whir.parseRoot(state, raw, 2);
        Whir.TwoCommitmentInitial memory initial = Whir.initializeTwoCommitments(
            state, raw, 2, 1, batchingPowBits, primaryStatements, secondaryStatements
        );
        state.finish(raw);
        return (
            primary.root,
            secondary.root,
            initial.target,
            initial.polynomialRandomness,
            initial.gamma,
            initial.theta
        );
    }

    function gammaWeights(Whir.Statement[] memory statements, uint256 gamma, uint256[] memory point)
        external
        pure
        returns (uint256)
    {
        return Whir.evaluateGammaStatementWeights(statements, gamma, point);
    }

    function sampleFirstTwoIndices(uint256 capacity0)
        external
        pure
        returns (uint256 first, uint256 second)
    {
        uint256[8] memory capacity;
        capacity[0] = capacity0;
        Transcript.State memory state = Transcript.initialize(capacity);
        first = state.sampleIndex(1);
        second = state.sampleIndex(1);
    }

    function dualStir(
        bytes calldata openings,
        bytes32 primaryRoot,
        bytes32 secondaryRoot,
        uint256 foldRandomness,
        uint256 polynomialRandomness,
        uint256 capacity0
    ) external pure returns (uint256 point, uint256 value) {
        uint256[8] memory capacity;
        capacity[0] = capacity0;
        Transcript.State memory state = Transcript.initialize(capacity);
        Whir.Cursor memory cursor;
        cursor.codec = 1;
        Whir.Round memory params = Whir.Round(0, 1, 4, 7, 1, 0, 0, 0);
        Whir.Commitment memory primary = Whir.Commitment(1, primaryRoot, new Whir.Statement[](0));
        Whir.Commitment memory secondary =
            Whir.Commitment(1, secondaryRoot, new Whir.Statement[](0));
        uint256[] memory foldPoint = new uint256[](1);
        foldPoint[0] = foldRandomness;
        Whir.Queries memory queries = Whir.stirTwoCommitments(
            state,
            openings[0:0],
            openings,
            cursor,
            params,
            primary,
            secondary,
            foldPoint,
            polynomialRandomness
        );
        require(cursor.offset == openings.length, "UNUSED_OPENING");
        return (queries.points[0], queries.values[0]);
    }
}

contract LeanVmWhirTwoCommitmentsTest is Test {
    uint256 private constant P = 2_130_706_433;
    uint256 private constant ONE = uint256(1) << 224;
    uint256 private constant DIGEST_MASK = type(uint256).max << 16;

    LeanVmWhirTwoCommitmentsHarness private harness;

    function setUp() external {
        harness = new LeanVmWhirTwoCommitmentsHarness();
    }

    function le32(uint256 value) private pure returns (bytes4) {
        return bytes4(
            uint32(
                ((value & 0xff) << 24) | ((value & 0xff00) << 8) | ((value >> 8) & 0xff00)
                    | (value >> 24)
            )
        );
    }

    function scalarBlock(uint256[] memory values) private pure returns (bytes memory out) {
        uint256 count = (values.length + 7) & ~uint256(7);
        for (uint256 i; i < count; ++i) {
            out = bytes.concat(out, le32(i < values.length ? values[i] : 0));
        }
    }

    function initialTranscript() private pure returns (bytes memory raw) {
        uint256[] memory primaryRoot = new uint256[](8);
        uint256[] memory secondaryRoot = new uint256[](8);
        for (uint256 i; i < 8; ++i) {
            primaryRoot[i] = i + 1;
            secondaryRoot[i] = i + 101;
        }
        uint256[] memory cross = new uint256[](10);
        cross[0] = 17;
        cross[5] = 19;
        uint256[] memory ood = new uint256[](5);
        ood[0] = 23;
        raw = bytes.concat(
            scalarBlock(primaryRoot),
            scalarBlock(secondaryRoot),
            scalarBlock(cross),
            scalarBlock(ood)
        );
    }

    function statements()
        private
        pure
        returns (Whir.Statement[] memory primary, Whir.Statement[] memory secondary)
    {
        primary = new Whir.Statement[](1);
        uint256[] memory primaryPoint = new uint256[](1);
        primaryPoint[0] = EF.fromBase(3);
        uint256[] memory primarySelectors = new uint256[](2);
        primarySelectors[1] = 1;
        uint256[] memory primaryValues = new uint256[](2);
        primaryValues[0] = EF.fromBase(5);
        primaryValues[1] = EF.fromBase(7);
        primary[0] = Whir.Statement(2, primaryPoint, primarySelectors, primaryValues, false);

        secondary = new Whir.Statement[](1);
        uint256[] memory secondaryPoint = new uint256[](2);
        secondaryPoint[0] = EF.fromBase(11);
        secondaryPoint[1] = EF.fromBase(13);
        uint256[] memory secondarySelectors = new uint256[](1);
        uint256[] memory secondaryValues = new uint256[](1);
        secondaryValues[0] = EF.fromBase(29);
        secondary[0] = Whir.Statement(2, secondaryPoint, secondarySelectors, secondaryValues, false);
    }

    function expectedDigest(uint256 start) private pure returns (bytes32) {
        uint256 packed;
        for (uint256 i; i < 8; ++i) {
            packed = (packed << 30) | (start + i);
        }
        return bytes32(packed << 16);
    }

    function testInitialTargetAndCoefficientOrder() external view {
        (Whir.Statement[] memory primary, Whir.Statement[] memory secondary) = statements();
        (
            bytes32 primaryRoot,
            bytes32 secondaryRoot,
            uint256 target,
            uint256 lambda,
            uint256 gamma,
            uint256 theta
        ) = harness.initialize(initialTranscript(), 0, primary, secondary);
        assertEq(primaryRoot, expectedDigest(1));
        assertEq(secondaryRoot, expectedDigest(101));

        // Value i of each group carries gamma^i; the groups carry theta^1 and theta^2.
        uint256 thetaSquared = EF.mulReference(theta, theta);
        uint256 expected = EF.fromBase(23);
        expected = EF.add(expected, EF.mulReference(theta, primary[0].values[0]));
        expected = EF.add(
            expected, EF.mulReference(theta, EF.mulReference(gamma, primary[0].values[1]))
        );
        expected =
            EF.add(expected, EF.mulReference(theta, EF.mulReference(lambda, EF.fromBase(17))));
        expected = EF.add(expected, EF.mulReference(thetaSquared, EF.fromBase(19)));
        expected = EF.add(
            expected, EF.mulReference(thetaSquared, EF.mulReference(lambda, secondary[0].values[0]))
        );
        assertEq(target, expected);
    }

    function testGammaWeightsUseGammaChainAndCommonFactor() external view {
        (Whir.Statement[] memory primary, Whir.Statement[] memory secondary) = statements();
        Whir.Statement[] memory both = new Whir.Statement[](2);
        both[0] = primary[0];
        both[1] = secondary[0];
        uint256 gamma = EF.fromBase(37);
        uint256[] memory point = new uint256[](2);
        point[0] = EF.fromBase(43);
        point[1] = EF.fromBase(47);

        uint256 primaryCommon = EF.eq_poly_eval(primary[0].point, suffix(point));
        uint256 zeroSelector = EF.sub(ONE, point[0]);
        uint256 oneSelector = point[0];
        uint256 expected = EF.mulReference(primaryCommon, zeroSelector);
        expected =
            EF.add(expected, EF.mulReference(gamma, EF.mulReference(primaryCommon, oneSelector)));
        uint256 gammaSquared = EF.mulReference(gamma, gamma);
        expected = EF.add(
            expected, EF.mulReference(gammaSquared, EF.eq_poly_eval(secondary[0].point, point))
        );
        assertEq(harness.gammaWeights(both, gamma, point), expected);
    }

    function suffix(uint256[] memory point) private pure returns (uint256[] memory out) {
        out = new uint256[](1);
        out[0] = point[1];
    }

    function row(uint256 a, uint256 b) private pure returns (bytes memory) {
        return abi.encodePacked(bytes4(uint32(a)), bytes4(uint32(b)));
    }

    function leaf(bytes memory encodedRow) private pure returns (bytes32) {
        return bytes32(uint256(keccak256(bytes.concat(hex"00", encodedRow))) & DIGEST_MASK);
    }

    function tree(uint256 a0, uint256 a1, uint256 b0, uint256 b1, uint256 index)
        private
        pure
        returns (bytes32 root, bytes memory opening, bytes memory selected)
    {
        bytes memory leftRow = row(a0, a1);
        bytes memory rightRow = row(b0, b1);
        bytes32 left = leaf(leftRow);
        bytes32 right = leaf(rightRow);
        root = bytes32(
            uint256(keccak256(abi.encodePacked(bytes1(0x01), left, right))) & DIGEST_MASK
        );
        selected = index == 0 ? leftRow : rightRow;
        opening = bytes.concat(selected, bytes30(index == 0 ? right : left));
    }

    function dualOpening(uint256 capacity0)
        private
        view
        returns (
            bytes memory openings,
            bytes32 primaryRoot,
            bytes32 secondaryRoot,
            bytes memory primaryOpening,
            bytes memory secondaryOpening,
            uint256 index
        )
    {
        (index,) = harness.sampleFirstTwoIndices(capacity0);
        bytes memory ignored;
        (primaryRoot, primaryOpening, ignored) = tree(2, 3, 5, 7, index);
        (secondaryRoot, secondaryOpening, ignored) = tree(11, 13, 17, 19, index);
        openings = bytes.concat(primaryOpening, secondaryOpening);
    }

    function distinctIndexCapacity() private view returns (uint256 capacity0) {
        for (capacity0 = 1; capacity0 < 64; ++capacity0) {
            (uint256 first, uint256 second) = harness.sampleFirstTwoIndices(capacity0);
            if (first != second) {
                return capacity0;
            }
        }
        revert("INDEX_SEARCH");
    }

    function foldPair(uint256 a, uint256 b, uint256 r) private pure returns (uint256) {
        return EF.add(EF.fromBase(a), EF.mulReference(r, EF.fromBase(addmod(b, P - a, P))));
    }

    function testDualStirUsesOneIndexAndPrimaryThenSecondary() external view {
        uint256 capacity0 = distinctIndexCapacity();
        (bytes memory openings, bytes32 primaryRoot, bytes32 secondaryRoot,,, uint256 index) =
            dualOpening(capacity0);
        uint256 r = EF.fromBase(23);
        uint256 lambda = EF.fromBase(29);
        (uint256 point, uint256 value) =
            harness.dualStir(openings, primaryRoot, secondaryRoot, r, lambda, capacity0);
        uint256 primary = index == 0 ? foldPair(2, 3, r) : foldPair(5, 7, r);
        uint256 secondary = index == 0 ? foldPair(11, 13, r) : foldPair(17, 19, r);
        assertEq(point, index == 0 ? 1 : 7);
        assertEq(value, EF.add(primary, EF.mulReference(lambda, secondary)));
    }

    function testRejectDualStirOpeningOrderAndRoots() external {
        uint256 capacity0 = distinctIndexCapacity();
        (
            bytes memory openings,
            bytes32 primaryRoot,
            bytes32 secondaryRoot,
            bytes memory primaryOpening,
            bytes memory secondaryOpening,
        ) = dualOpening(capacity0);
        vm.expectRevert("MERKLE_ROOT");
        harness.dualStir(
            bytes.concat(secondaryOpening, primaryOpening),
            primaryRoot,
            secondaryRoot,
            EF.fromBase(23),
            EF.fromBase(29),
            capacity0
        );
        vm.expectRevert("MERKLE_ROOT");
        harness.dualStir(
            openings,
            bytes32(uint256(primaryRoot) ^ (uint256(1) << 255)),
            secondaryRoot,
            EF.fromBase(23),
            EF.fromBase(29),
            capacity0
        );
    }

    function testRejectInitialPaddingTrailingInputAndWrongBatchingBits() external {
        (Whir.Statement[] memory primary, Whir.Statement[] memory secondary) = statements();
        bytes memory raw = initialTranscript();
        raw[104] = 0x01;
        vm.expectRevert("TRANSCRIPT_PADDING");
        harness.initialize(raw, 0, primary, secondary);

        raw = bytes.concat(initialTranscript(), hex"00");
        vm.expectRevert("UNUSED_TRANSCRIPT");
        harness.initialize(raw, 0, primary, secondary);

        vm.expectRevert();
        harness.initialize(initialTranscript(), 1, primary, secondary);
    }

    function testRootsCrossValuesAndOodAnswerAffectLaterChallenges() external view {
        (Whir.Statement[] memory primary, Whir.Statement[] memory secondary) = statements();
        bytes memory raw = initialTranscript();
        (,,, uint256 baseLambda,, uint256 baseTheta) =
            harness.initialize(raw, 0, primary, secondary);

        bytes memory changedRoot = initialTranscript();
        changedRoot[0] ^= 0x01;
        (,,, uint256 rootLambda,,) = harness.initialize(changedRoot, 0, primary, secondary);
        assertTrue(rootLambda != baseLambda);

        bytes memory changedCross = initialTranscript();
        changedCross[64] ^= 0x01;
        (,,, uint256 crossLambda,,) = harness.initialize(changedCross, 0, primary, secondary);
        assertTrue(crossLambda != baseLambda);

        bytes memory changedOod = initialTranscript();
        changedOod[128] ^= 0x01;
        (,,,,, uint256 oodTheta) = harness.initialize(changedOod, 0, primary, secondary);
        assertTrue(oodTheta != baseTheta);
    }

    function testRejectTrailingOpening() external {
        uint256 capacity0 = distinctIndexCapacity();
        (bytes memory openings, bytes32 primaryRoot, bytes32 secondaryRoot,,,) =
            dualOpening(capacity0);
        vm.expectRevert("UNUSED_OPENING");
        harness.dualStir(
            bytes.concat(openings, hex"00"),
            primaryRoot,
            secondaryRoot,
            EF.fromBase(23),
            EF.fromBase(29),
            capacity0
        );
    }
}
