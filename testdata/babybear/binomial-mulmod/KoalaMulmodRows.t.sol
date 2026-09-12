// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import {Test} from "forge-std/Test.sol";
import {BabyBearReference as Ref} from "./helpers/BabyBearReference.sol";
import {KoalaBearRowCombinedFollowupHarness,KoalaBearRowMulmodHarness} from "./helpers/Rows.sol";
interface IRowFollowupHarness {function batch(bytes calldata,uint256[4] memory,uint256) external view returns(uint256,uint256,uint256,bytes32);function dot(uint256[16] memory,uint256[16] memory) external view returns(uint256,uint256);}
contract KoalaMulmodRowsTest is Test {
    IRowFollowupHarness[2] h;

    function setUp() external {h[0]=IRowFollowupHarness(address(new KoalaBearRowCombinedFollowupHarness()));h[1]=IRowFollowupHarness(address(new KoalaBearRowMulmodHarness()));}
    function _packed(bytes32 seed, uint256 index, uint256 p) private pure returns (uint256) {
        uint256[5] memory a;
        for (uint256 j; j < 5; ++j) {
            a[j] = uint256(keccak256(abi.encode(seed, index, j))) % p;
        }
        return Ref.pack(a);
    }

    function _blob(bytes32 seed, uint256 count, uint256 p)
        private
        pure
        returns (bytes memory blob)
    {
        blob = new bytes(count * 320 + 32);
        for (uint256 i; i < count * 16; ++i) {
            uint256 value = _packed(seed, i, p);
            assembly ("memory-safe") { mstore(add(add(blob, 32), mul(i, 20)), value) }
        }
        assembly ("memory-safe") { mstore(blob, mul(count, 320)) }
    }

    function _checkOracle(bytes memory blob, uint256[4] memory point, uint256 p, uint256 f)
        private
        view
    {
        uint256 expected;
        bytes memory leaf = new bytes(321);
        for (uint256 i; i < 320; ++i) {
            leaf[i + 1] = blob[i];
        }
        for (uint256 i; i < 16; ++i) {
            uint256 weight = uint256(1) << 224;
            for (uint256 j; j < 4; ++j) {
                uint256 factor = ((i >> (3 - j)) & 1) != 0
                    ? point[j]
                    : Ref.add(uint256(1) << 224, Ref.scale(point[j], p - 1, p), p);
                weight = Ref.mul(weight, factor, p, f);
            }
            uint256 value;
            assembly ("memory-safe") {
                value := and(mload(add(add(blob, 32), mul(i, 20))), not(sub(shl(96, 1), 1)))
            }
            expected = Ref.add(expected, Ref.mul(value, weight, p, f), p);
        }
        for(uint256 i;i<2;++i) {
            (,, uint256 actual, bytes32 digest) = h[i].batch(blob, point, 1);
            assertEq(actual, expected, "schoolbook multilinear row");
            assertEq(digest, bytes32(bytes20(keccak256(leaf))), "prefixed original row hash");
            assertEq(actual & ((uint256(1) << 96) - 1), 0, "unused packed bits");
            for (uint256 j; j < 5; ++j) {
                assertLt((actual >> (224 - 32 * j)) & 0xffffffff, p, "canonical output");
            }
        }
    }

    function testFuzzFullRowOracle(bytes32 seed) external view {
        for (uint256 f=0; f < 1; ++f) {
            uint256 p = f == 0 ? 0x7f000001 : 0x78000001;
            uint256[4] memory point;
            for (uint256 j; j < 4; ++j) {
                point[j] = _packed(seed, j, p);
            }
            _checkOracle(_blob(seed, 1, p), point, p, f);
        }
    }

    function testZeroOneAndMaximalRows() external view {
        for (uint256 f=0; f < 1; ++f) {
            uint256 p = f == 0 ? 0x7f000001 : 0x78000001;
            uint256 maximum = Ref.pack([p - 1, p - 1, p - 1, p - 1, p - 1]);
            bytes memory blob = new bytes(352);
            for (uint256 i; i < 16; ++i) {
                assembly ("memory-safe") { mstore(add(add(blob, 32), mul(i, 20)), maximum) }
            }
            assembly ("memory-safe") { mstore(blob, 320) }
            for (uint256 mode; mode < 3; ++mode) {
                uint256[4] memory point;
                for (uint256 j; j < 4; ++j) {
                    point[j] = mode == 0 ? 0 : (mode == 1 ? uint256(1) << 224 : maximum);
                }
                _checkOracle(blob, point, p, f);
            }
        }
    }

    function testMalformedEveryLaneAndHighBit() external {
        uint256[4] memory point;
        for (uint256 f=0; f < 1; ++f) {
            uint256 p = f == 0 ? 0x7f000001 : 0x78000001;
            uint256[4] memory malformed = [p, p + 1, uint256(0x80000000), uint256(0xffffffff)];
            for (uint256 element; element < 16; ++element) {
                for (uint256 lane; lane < 5; ++lane) {
                    for (uint256 k; k < 4; ++k) {
                        bytes memory blob = new bytes(352);
                        uint256 bad = malformed[k] << (224 - 32 * lane);
                        assembly ("memory-safe") {
                            mstore(blob, 320)
                            mstore(add(add(blob, 32), mul(element, 20)), bad)
                        }
                        for(uint256 i;i<2;++i) {
                            vm.expectRevert(abi.encodeWithSelector(bytes4(0xd53cfe5c), bad));
                            h[i].batch(blob, point, 1);
                        }
                    }
                }
            }
        }
    }

    function testFirstMalformedElementPreserved() external {
        uint256[4] memory point;
        bytes memory blob = new bytes(352);
        uint256 first = uint256(0xffffffff) << 224;
        uint256 second = uint256(0x80000000) << 96;
        assembly ("memory-safe") {
            mstore(blob, 320)
            mstore(add(blob, 72), first)
            mstore(add(blob, 312), second)
        }
        for(uint256 i;i<2;++i) {
            vm.expectRevert(abi.encodeWithSelector(bytes4(0xd53cfe5c), first));
            h[i].batch(blob, point, 1);
        }
    }

    function testBenchmarkFollowupRows() external {
        string[2] memory names=["KoalaCombined","KoalaMulmod"];
        uint256[4] memory point;
        for (uint256 j; j < 4; ++j) {
            point[j] = _packed(bytes32(uint256(67)), j, 0x78000001);
        }
        uint256[3] memory counts = [uint256(31), 19, 14];
        for(uint256 i;i<2;++i) {
            uint256 total;
            for (uint256 r; r < 3; ++r) {
                bytes memory blob = _blob(bytes32(uint256(73 + r)), counts[r], 0x78000001);
                (uint256 setupGas, uint256 rowGas, uint256 value, bytes32 digest) =
                    h[i].batch(blob, point, counts[r]);
                emit log_named_uint(
                    string.concat(names[i], ".setup", vm.toString(counts[r])), setupGas
                );
                emit log_named_uint(
                    string.concat(names[i], ".rows", vm.toString(counts[r])), rowGas
                );
                total += setupGas + rowGas;
                assertTrue(value != 0 && digest != 0);
            }
            emit log_named_uint(string.concat(names[i], ".total"), total);
        }
    }

    function testProfileSelectedBabyRows() external view {
        uint256[4] memory point;
        for (uint256 j; j < 4; ++j) {
            point[j] = _packed(bytes32(uint256(67)), j, 0x78000001);
        }
        (,, uint256 value,) = h[1].batch(_blob(bytes32(uint256(73)), 31, 0x78000001), point, 31);
        assertTrue(value != 0);
    }
function testFuzzIndependentDot(bytes32 seed) external view {uint256[16] memory a;uint256[16] memory b;uint256 expected;for(uint256 i;i<16;++i){a[i]=_packed(seed,i,0x7f000001);b[i]=_packed(seed,i+16,0x7f000001);expected=Ref.add(expected,Ref.mul(a[i],b[i],0x7f000001,0),0x7f000001);}for(uint256 j;j<2;++j){(,uint256 actual)=h[j].dot(a,b);assertEq(actual,expected);}}
function testMaximalDotAndBasis() external{uint256 Q=0x7f000001;uint256[16] memory a;uint256[16] memory b;uint256 max=Ref.pack([Q-1,Q-1,Q-1,Q-1,Q-1]);for(uint256 i;i<16;++i){a[i]=max;b[i]=max;}uint256 expected=Ref.scale(Ref.mul(max,max,Q,0),16,Q);for(uint256 j;j<2;++j){(uint256 used,uint256 actual)=h[j].dot(a,b);assertEq(actual,expected);emit log_named_uint(j==0?"KoalaCombined.dot":"KoalaMulmod.dot",used);}for(uint256 i;i<5;++i)for(uint256 j;j<5;++j){for(uint256 z;z<16;++z){a[z]=(Q-1)<<(224-32*i);b[z]=(Q-1)<<(224-32*j);}expected=Ref.scale(Ref.mul(a[0],b[0],Q,0),16,Q);(,uint256 actual)=h[1].dot(a,b);assertEq(actual,expected);}}
}
