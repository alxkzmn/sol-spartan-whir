// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import {Test} from "forge-std/Test.sol";
import {BabyBearReference as Ref} from "./helpers/BabyBearReference.sol";
import {BabyBearChainFusedConsumerHarness} from "./helpers/SelectExperiments.sol";
contract SelectedBabyExtendedTest is Test {
    BabyBearChainFusedConsumerHarness h;
    uint256 constant P=0x78000001;
    function setUp() external { h=new BabyBearChainFusedConsumerHarness(); }
    function extension(bytes32 seed,uint256 tag) private pure returns(uint256) {
        uint256[5] memory a;
        for(uint256 j;j<5;++j) a[j]=uint256(keccak256(abi.encode(seed,tag,j)))%P;
        return Ref.pack(a);
    }
    function check(uint256[] memory v,uint256[][3] memory sels,uint256[3] memory ch,uint256[3] memory eq) private view {
        uint256[3] memory expected;
        for(uint256 r;r<3;++r) {
            uint256 n=18-4*r;
            for(uint256 i=sels[r].length;i>0;--i)
                expected[r]=Ref.add(Ref.mul(expected[r],ch[r],P,1),Ref.chain(sels[r][i-1],v,22-n,n,P,1),P);
            expected[r]=Ref.add(Ref.mul(expected[r],ch[r],P,1),eq[r],P);
        }
        (,uint256[3] memory actual)=h.batch(v,sels,ch,eq);
        assertEq(abi.encode(actual),abi.encode(expected));
        for(uint256 r;r<3;++r) {
            uint256[5] memory coeff=Ref.unpack(actual[r]);
            for(uint256 i;i<5;++i) assertLt(coeff[i],P);
            assertEq(actual[r]&((uint256(1)<<96)-1),0);
        }
    }
    function testFuzzSelectedFullBatch(bytes32 seed) external view {
        uint256[] memory v=new uint256[](22);
        for(uint256 i;i<22;++i) v[i]=extension(seed,i);
        uint256[][3] memory sels; uint256[3] memory ch; uint256[3] memory eq;
        uint256[3] memory counts=[uint256(38),31,19];
        for(uint256 r;r<3;++r) {
            sels[r]=new uint256[](counts[r]);
            for(uint256 i;i<counts[r];++i) sels[r][i]=uint256(keccak256(abi.encode(seed,r,i,"selector")))%P;
            ch[r]=extension(seed,22+2*r); eq[r]=extension(seed,23+2*r);
        }
        check(v,sels,ch,eq);
    }
    function boundary(uint256 a,uint256 b) private view {
        uint256 max=Ref.pack([P-1,P-1,P-1,P-1,P-1]);
        uint256[] memory v=new uint256[](22);uint256[][3] memory sels;uint256[3] memory ch;uint256[3] memory eq;
        uint256[3] memory counts=[uint256(38),31,19];
        uint256 pointValue=a==0?0:(a==1?uint256(1)<<224:(a==2?max:(P-1)<<(224-32*(a-3))));
        uint256 challengeValue=b==0?0:(b==1?uint256(1)<<224:(b==2?max:(P-1)<<(224-32*(b-3))));
        for(uint256 i;i<22;++i) v[i]=pointValue;
        for(uint256 r;r<3;++r) {
            sels[r]=new uint256[](counts[r]);
            for(uint256 i;i<counts[r];++i) sels[r][i]=i%3==0?0:(i%3==1?1:P-1);
            ch[r]=challengeValue;eq[r]=max;
        }
        check(v,sels,ch,eq);
    }
    function testBoundary_0_0() external view {boundary(0,0);}
    function testBoundary_0_1() external view {boundary(0,1);}
    function testBoundary_0_2() external view {boundary(0,2);}
    function testBoundary_0_3() external view {boundary(0,3);}
    function testBoundary_0_4() external view {boundary(0,4);}
    function testBoundary_0_5() external view {boundary(0,5);}
    function testBoundary_0_6() external view {boundary(0,6);}
    function testBoundary_0_7() external view {boundary(0,7);}
    function testBoundary_1_0() external view {boundary(1,0);}
    function testBoundary_1_1() external view {boundary(1,1);}
    function testBoundary_1_2() external view {boundary(1,2);}
    function testBoundary_1_3() external view {boundary(1,3);}
    function testBoundary_1_4() external view {boundary(1,4);}
    function testBoundary_1_5() external view {boundary(1,5);}
    function testBoundary_1_6() external view {boundary(1,6);}
    function testBoundary_1_7() external view {boundary(1,7);}
    function testBoundary_2_0() external view {boundary(2,0);}
    function testBoundary_2_1() external view {boundary(2,1);}
    function testBoundary_2_2() external view {boundary(2,2);}
    function testBoundary_2_3() external view {boundary(2,3);}
    function testBoundary_2_4() external view {boundary(2,4);}
    function testBoundary_2_5() external view {boundary(2,5);}
    function testBoundary_2_6() external view {boundary(2,6);}
    function testBoundary_2_7() external view {boundary(2,7);}
    function testBoundary_3_0() external view {boundary(3,0);}
    function testBoundary_3_1() external view {boundary(3,1);}
    function testBoundary_3_2() external view {boundary(3,2);}
    function testBoundary_3_3() external view {boundary(3,3);}
    function testBoundary_3_4() external view {boundary(3,4);}
    function testBoundary_3_5() external view {boundary(3,5);}
    function testBoundary_3_6() external view {boundary(3,6);}
    function testBoundary_3_7() external view {boundary(3,7);}
    function testBoundary_4_0() external view {boundary(4,0);}
    function testBoundary_4_1() external view {boundary(4,1);}
    function testBoundary_4_2() external view {boundary(4,2);}
    function testBoundary_4_3() external view {boundary(4,3);}
    function testBoundary_4_4() external view {boundary(4,4);}
    function testBoundary_4_5() external view {boundary(4,5);}
    function testBoundary_4_6() external view {boundary(4,6);}
    function testBoundary_4_7() external view {boundary(4,7);}
    function testBoundary_5_0() external view {boundary(5,0);}
    function testBoundary_5_1() external view {boundary(5,1);}
    function testBoundary_5_2() external view {boundary(5,2);}
    function testBoundary_5_3() external view {boundary(5,3);}
    function testBoundary_5_4() external view {boundary(5,4);}
    function testBoundary_5_5() external view {boundary(5,5);}
    function testBoundary_5_6() external view {boundary(5,6);}
    function testBoundary_5_7() external view {boundary(5,7);}
    function testBoundary_6_0() external view {boundary(6,0);}
    function testBoundary_6_1() external view {boundary(6,1);}
    function testBoundary_6_2() external view {boundary(6,2);}
    function testBoundary_6_3() external view {boundary(6,3);}
    function testBoundary_6_4() external view {boundary(6,4);}
    function testBoundary_6_5() external view {boundary(6,5);}
    function testBoundary_6_6() external view {boundary(6,6);}
    function testBoundary_6_7() external view {boundary(6,7);}
    function testBoundary_7_0() external view {boundary(7,0);}
    function testBoundary_7_1() external view {boundary(7,1);}
    function testBoundary_7_2() external view {boundary(7,2);}
    function testBoundary_7_3() external view {boundary(7,3);}
    function testBoundary_7_4() external view {boundary(7,4);}
    function testBoundary_7_5() external view {boundary(7,5);}
    function testBoundary_7_6() external view {boundary(7,6);}
    function testBoundary_7_7() external view {boundary(7,7);}
}
