// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// Poseidon1 over KoalaBear: width 16, cubic S-box, 8 full and 20 partial rounds.
library LeanVmPoseidon1DenseReference {
    uint256 internal constant MODULUS = 2_130_706_433;
    bytes private constant ROUND_CONSTANTS =
        hex"7ee56a481136704512e419417ebbc12b1970b7d5662b60e83e4990c6679f91f5350813bb00874ad428a0081a18fa58725f25b0715e5d59985e6fd3e75b2e26606f1837bf3fe6182b1edd7ac557470d0043d486d51982c70f0ea53af961d6165b51639c002dec352c2950e5312d2cb94708256cef1a0109f61f51faf35cef1c623d65e50e33d91626133d5a1e0ff49b0d38900cd12c22cc3f28852bb206c65a027b2cf7bc68016e1a15e16bc05248149a6dd212a018d6830a5001be8264dac34e5902b287426583a00c9216323fe028a5245f8e4943bb297e7873dbd93cc987df286bb4ce640a8dcd512a8e3603a4cf55481837a203d6da8473726ac7760e7fdf54dfeb5d7d40afd6722cb316106a457345a7ccdb44061375154077a545744faa4eb5e5ee3794e83f47c7093c5694903c69cb6299373df84c46a0df5846b8758a3241ebcb0b09d2331af423571e66cec243e7dc24259a5d6127e85a3b1b9133fa343e5628485cd4c216e269f5165b60c625f683d9124f81f9174331f977344dc55a821dba5fc4177f54153bf55e3f11943bdbf191088c84a368256c9b3c90bbc66846166a03f4238d463335fb5e3d35516e59ae6f32d06cc0596293f36c87edb208fc60b534bcca8024f007f362731c6f1e1db6c60ca409bb585c1e7856e94edc16d2273418e114677b2c3730770075e435d1b18c22be3db54fb1fbb7477cb3ed7d5311c65b62ae7d559c5fa877f150483211570b490fef6a77ec311f2247171b4e0ac7112edf69c93b5a8850658094215619b4aa362019a76bf9d4ed5b413dff617e181e5e7ab57b33ad78333466c7ca6488dff471f068f4056e891f04f1eccc663257d5671e31b95871987c280c109e2a227761350a25e95b91b1c47a0735460182627053a677200ed4b07434cf0c4e6e751e8829bd5f5949ec32df7693452b3cf09e586ba0e2bf7ab93acf3ce597df536e3d42147a808d5e32eb565a203323509657666d44b7c56698636a57b84f9f554b61b96da0ab281585b6ac6705a2b4152872f60f4409fd23a9dd606f2b18d465ac9fd42f0efbea591e67fd217ca19b469c90ca03d60ef54ea7857e07c86a4f288ed4612fe51b227e2936142c4beb855b0b7d111e17dff6089beae10a5acf1a2fc33d8f60422dc66e1dc939635351b955522fc03eb94ef72a24a65c2e139c765139114478cc0742579538f944de9aae3c2f1e2e195747be2496339c650b2e39528996656cb355580f461c1c70f6b2703faaa36f62e3348a672167cb394c880b2a46ba8263ffb74a1cf875d653d12772036a45523bdd9f2b02f72c2402b6006c077fe1581f9d6ea420904d6f5d6534fa066d89746198f1f426301ab441f274c200eac15c28b54b472339739d48c6281c4ed935fc3f9187fa4a1930a63ad4d7360f3f1889635a388f2862c145277ed1e84db23cad1f1b11f51f3dba2b1c26eb4e0f7f55466cd024b067c47902793b89000e8a283c4590b7ea6f567a2b5dc9730015247bc650567fcb133eff84547dc2ef34eb3dbb1240231766c6ae49174338b6242510081b514927062d98d67af30bbc26af15e870d907a35dfc5cac731f27ec53aa7d3f63ab0ec6216053f418796b3919156afd5eea69736704c6a90dce002b331169c0714d71783ddaffaf7e46495720ca59ea679820c942ef21a1798ea08914a74fa30c06cf186a4c8d52620f6d812220901a5277bb90230bf95e0ad8847a5e96e8b677b4056e70a50d2c5f0eed593646c4df10eb9a8721eed6b7534add366e3e74212b25810e1d8f707b45318a1a677f8ff20258c9e04cd02a002e24ff15634a715d4ac01e59601511e126e9c01a4c165c6e57cd11403ac6543b6787d847037dfbf96dd9d0794d24b2812a6f407d0131df8e4b8a7896237008582cf5e53412aafc3f54568d031a2507355331686d4ce76d91799c1a8c2b7a8ac960aee67274f7421c3c42146d26d369c54ae54a127eea16d15ce3eae869f28994262b8642610d4cc45e1af21c1a8526d0316b127b3576fe5d02d968a04ba00f5140bed993377fb9077859216e1931d9d153b0934e71914ff74eabae6c7196468e164b3cc258cb66c04c1473076b3afccd4236518b4ad85605291382e11e89b6cf5e16c3a82e6759212430095405e555c378880a24763a31254f53b24018b7fa432bbe8a731c9a12f23f6fd40d0e1d4ec41361c64d09a8f47003d23a40109ad29028c2fb883b6498f274d8be576a4277d218c2b3d46252c30c07cc2560209fe15b52a55fac4df19eb7025211165e414ff13cd9a1f4005aad1527a53f0072bbe9cb71d8bd7d4194b79a48e87a723341553c63d34faa132a01e33833e2d949726e04054957f87b71bce473eec57d556e55331fa93fde346a8ca81162dfde5c30d028094a42943052dcda3798849851f06b97658487797599b0d4436fdabc66c5b77d40c86a9e27e7055b6d0dd9d87e5598b51a4d04f35e3b2bc7533b5b2f3e33a125664d71ce382e6c2a24c4eb6e13f246f707e2d7ef";
    error NonCanonicalField();
    error InvalidLeafLength();

    function permute(uint256[16] memory state) internal pure {
        bytes memory constants = ROUND_CONSTANTS;
        assembly ("memory-safe") {
            let p := 2130706433
            let scratch := mload(0x40)
            mstore(0x40, add(scratch, 512))
            for { let round := 0 } lt(round, 28) { round := add(round, 1) } {
                for { let i := 0 } lt(i, 16) { i := add(i, 1) } {
                    let slot := add(state, shl(5, i))
                    let constant :=
                        shr(224, mload(add(add(constants, 32), add(mul(round, 64), shl(2, i)))))
                    let x := addmod(mload(slot), constant, p)
                    if or(or(lt(round, 4), gt(round, 23)), iszero(i)) {
                        x := mulmod(mulmod(x, x, p), x, p)
                    }
                    mstore(slot, x)
                }
                mstore(
                    add(scratch, 0),
                    mod(
                        add(
                            add(
                                add(
                                    add(
                                        add(
                                            add(
                                                add(
                                                    add(
                                                        add(
                                                            add(
                                                                add(
                                                                    add(
                                                                        add(
                                                                            add(
                                                                                add(
                                                                                    mload(add(state, 0)),
                                                                                    mload(add(state, 32))
                                                                                ),
                                                                                mul(mload(add(state, 64)), 51)
                                                                            ),
                                                                            mload(add(state, 96))
                                                                        ),
                                                                        mul(mload(add(state, 128)), 11)
                                                                    ),
                                                                    mul(mload(add(state, 160)), 17)
                                                                ),
                                                                mul(mload(add(state, 192)), 2)
                                                            ),
                                                            mload(add(state, 224))
                                                        ),
                                                        mul(mload(add(state, 256)), 101)
                                                    ),
                                                    mul(mload(add(state, 288)), 63)
                                                ),
                                                mul(mload(add(state, 320)), 15)
                                            ),
                                            mul(mload(add(state, 352)), 2)
                                        ),
                                        mul(mload(add(state, 384)), 67)
                                    ),
                                    mul(mload(add(state, 416)), 22)
                                ),
                                mul(mload(add(state, 448)), 13)
                            ),
                            mul(mload(add(state, 480)), 3)
                        ),
                        p
                    )
                )
                mstore(
                    add(scratch, 32),
                    mod(
                        add(
                            add(
                                add(
                                    add(
                                        add(
                                            add(
                                                add(
                                                    add(
                                                        add(
                                                            add(
                                                                add(
                                                                    add(
                                                                        add(
                                                                            add(
                                                                                add(
                                                                                    mul(mload(add(state, 0)), 3),
                                                                                    mload(add(state, 32))
                                                                                ),
                                                                                mload(add(state, 64))
                                                                            ),
                                                                            mul(mload(add(state, 96)), 51)
                                                                        ),
                                                                        mload(add(state, 128))
                                                                    ),
                                                                    mul(mload(add(state, 160)), 11)
                                                                ),
                                                                mul(mload(add(state, 192)), 17)
                                                            ),
                                                            mul(mload(add(state, 224)), 2)
                                                        ),
                                                        mload(add(state, 256))
                                                    ),
                                                    mul(mload(add(state, 288)), 101)
                                                ),
                                                mul(mload(add(state, 320)), 63)
                                            ),
                                            mul(mload(add(state, 352)), 15)
                                        ),
                                        mul(mload(add(state, 384)), 2)
                                    ),
                                    mul(mload(add(state, 416)), 67)
                                ),
                                mul(mload(add(state, 448)), 22)
                            ),
                            mul(mload(add(state, 480)), 13)
                        ),
                        p
                    )
                )
                mstore(
                    add(scratch, 64),
                    mod(
                        add(
                            add(
                                add(
                                    add(
                                        add(
                                            add(
                                                add(
                                                    add(
                                                        add(
                                                            add(
                                                                add(
                                                                    add(
                                                                        add(
                                                                            add(
                                                                                add(
                                                                                    mul(mload(add(state, 0)), 13),
                                                                                    mul(mload(add(state, 32)), 3)
                                                                                ),
                                                                                mload(add(state, 64))
                                                                            ),
                                                                            mload(add(state, 96))
                                                                        ),
                                                                        mul(mload(add(state, 128)), 51)
                                                                    ),
                                                                    mload(add(state, 160))
                                                                ),
                                                                mul(mload(add(state, 192)), 11)
                                                            ),
                                                            mul(mload(add(state, 224)), 17)
                                                        ),
                                                        mul(mload(add(state, 256)), 2)
                                                    ),
                                                    mload(add(state, 288))
                                                ),
                                                mul(mload(add(state, 320)), 101)
                                            ),
                                            mul(mload(add(state, 352)), 63)
                                        ),
                                        mul(mload(add(state, 384)), 15)
                                    ),
                                    mul(mload(add(state, 416)), 2)
                                ),
                                mul(mload(add(state, 448)), 67)
                            ),
                            mul(mload(add(state, 480)), 22)
                        ),
                        p
                    )
                )
                mstore(
                    add(scratch, 96),
                    mod(
                        add(
                            add(
                                add(
                                    add(
                                        add(
                                            add(
                                                add(
                                                    add(
                                                        add(
                                                            add(
                                                                add(
                                                                    add(
                                                                        add(
                                                                            add(
                                                                                add(
                                                                                    mul(mload(add(state, 0)), 22),
                                                                                    mul(mload(add(state, 32)), 13)
                                                                                ),
                                                                                mul(mload(add(state, 64)), 3)
                                                                            ),
                                                                            mload(add(state, 96))
                                                                        ),
                                                                        mload(add(state, 128))
                                                                    ),
                                                                    mul(mload(add(state, 160)), 51)
                                                                ),
                                                                mload(add(state, 192))
                                                            ),
                                                            mul(mload(add(state, 224)), 11)
                                                        ),
                                                        mul(mload(add(state, 256)), 17)
                                                    ),
                                                    mul(mload(add(state, 288)), 2)
                                                ),
                                                mload(add(state, 320))
                                            ),
                                            mul(mload(add(state, 352)), 101)
                                        ),
                                        mul(mload(add(state, 384)), 63)
                                    ),
                                    mul(mload(add(state, 416)), 15)
                                ),
                                mul(mload(add(state, 448)), 2)
                            ),
                            mul(mload(add(state, 480)), 67)
                        ),
                        p
                    )
                )
                mstore(
                    add(scratch, 128),
                    mod(
                        add(
                            add(
                                add(
                                    add(
                                        add(
                                            add(
                                                add(
                                                    add(
                                                        add(
                                                            add(
                                                                add(
                                                                    add(
                                                                        add(
                                                                            add(
                                                                                add(
                                                                                    mul(mload(add(state, 0)), 67),
                                                                                    mul(mload(add(state, 32)), 22)
                                                                                ),
                                                                                mul(mload(add(state, 64)), 13)
                                                                            ),
                                                                            mul(mload(add(state, 96)), 3)
                                                                        ),
                                                                        mload(add(state, 128))
                                                                    ),
                                                                    mload(add(state, 160))
                                                                ),
                                                                mul(mload(add(state, 192)), 51)
                                                            ),
                                                            mload(add(state, 224))
                                                        ),
                                                        mul(mload(add(state, 256)), 11)
                                                    ),
                                                    mul(mload(add(state, 288)), 17)
                                                ),
                                                mul(mload(add(state, 320)), 2)
                                            ),
                                            mload(add(state, 352))
                                        ),
                                        mul(mload(add(state, 384)), 101)
                                    ),
                                    mul(mload(add(state, 416)), 63)
                                ),
                                mul(mload(add(state, 448)), 15)
                            ),
                            mul(mload(add(state, 480)), 2)
                        ),
                        p
                    )
                )
                mstore(
                    add(scratch, 160),
                    mod(
                        add(
                            add(
                                add(
                                    add(
                                        add(
                                            add(
                                                add(
                                                    add(
                                                        add(
                                                            add(
                                                                add(
                                                                    add(
                                                                        add(
                                                                            add(
                                                                                add(
                                                                                    mul(mload(add(state, 0)), 2),
                                                                                    mul(mload(add(state, 32)), 67)
                                                                                ),
                                                                                mul(mload(add(state, 64)), 22)
                                                                            ),
                                                                            mul(mload(add(state, 96)), 13)
                                                                        ),
                                                                        mul(mload(add(state, 128)), 3)
                                                                    ),
                                                                    mload(add(state, 160))
                                                                ),
                                                                mload(add(state, 192))
                                                            ),
                                                            mul(mload(add(state, 224)), 51)
                                                        ),
                                                        mload(add(state, 256))
                                                    ),
                                                    mul(mload(add(state, 288)), 11)
                                                ),
                                                mul(mload(add(state, 320)), 17)
                                            ),
                                            mul(mload(add(state, 352)), 2)
                                        ),
                                        mload(add(state, 384))
                                    ),
                                    mul(mload(add(state, 416)), 101)
                                ),
                                mul(mload(add(state, 448)), 63)
                            ),
                            mul(mload(add(state, 480)), 15)
                        ),
                        p
                    )
                )
                mstore(
                    add(scratch, 192),
                    mod(
                        add(
                            add(
                                add(
                                    add(
                                        add(
                                            add(
                                                add(
                                                    add(
                                                        add(
                                                            add(
                                                                add(
                                                                    add(
                                                                        add(
                                                                            add(
                                                                                add(
                                                                                    mul(mload(add(state, 0)), 15),
                                                                                    mul(mload(add(state, 32)), 2)
                                                                                ),
                                                                                mul(mload(add(state, 64)), 67)
                                                                            ),
                                                                            mul(mload(add(state, 96)), 22)
                                                                        ),
                                                                        mul(mload(add(state, 128)), 13)
                                                                    ),
                                                                    mul(mload(add(state, 160)), 3)
                                                                ),
                                                                mload(add(state, 192))
                                                            ),
                                                            mload(add(state, 224))
                                                        ),
                                                        mul(mload(add(state, 256)), 51)
                                                    ),
                                                    mload(add(state, 288))
                                                ),
                                                mul(mload(add(state, 320)), 11)
                                            ),
                                            mul(mload(add(state, 352)), 17)
                                        ),
                                        mul(mload(add(state, 384)), 2)
                                    ),
                                    mload(add(state, 416))
                                ),
                                mul(mload(add(state, 448)), 101)
                            ),
                            mul(mload(add(state, 480)), 63)
                        ),
                        p
                    )
                )
                mstore(
                    add(scratch, 224),
                    mod(
                        add(
                            add(
                                add(
                                    add(
                                        add(
                                            add(
                                                add(
                                                    add(
                                                        add(
                                                            add(
                                                                add(
                                                                    add(
                                                                        add(
                                                                            add(
                                                                                add(
                                                                                    mul(mload(add(state, 0)), 63),
                                                                                    mul(mload(add(state, 32)), 15)
                                                                                ),
                                                                                mul(mload(add(state, 64)), 2)
                                                                            ),
                                                                            mul(mload(add(state, 96)), 67)
                                                                        ),
                                                                        mul(mload(add(state, 128)), 22)
                                                                    ),
                                                                    mul(mload(add(state, 160)), 13)
                                                                ),
                                                                mul(mload(add(state, 192)), 3)
                                                            ),
                                                            mload(add(state, 224))
                                                        ),
                                                        mload(add(state, 256))
                                                    ),
                                                    mul(mload(add(state, 288)), 51)
                                                ),
                                                mload(add(state, 320))
                                            ),
                                            mul(mload(add(state, 352)), 11)
                                        ),
                                        mul(mload(add(state, 384)), 17)
                                    ),
                                    mul(mload(add(state, 416)), 2)
                                ),
                                mload(add(state, 448))
                            ),
                            mul(mload(add(state, 480)), 101)
                        ),
                        p
                    )
                )
                mstore(
                    add(scratch, 256),
                    mod(
                        add(
                            add(
                                add(
                                    add(
                                        add(
                                            add(
                                                add(
                                                    add(
                                                        add(
                                                            add(
                                                                add(
                                                                    add(
                                                                        add(
                                                                            add(
                                                                                add(
                                                                                    mul(mload(add(state, 0)), 101),
                                                                                    mul(mload(add(state, 32)), 63)
                                                                                ),
                                                                                mul(mload(add(state, 64)), 15)
                                                                            ),
                                                                            mul(mload(add(state, 96)), 2)
                                                                        ),
                                                                        mul(mload(add(state, 128)), 67)
                                                                    ),
                                                                    mul(mload(add(state, 160)), 22)
                                                                ),
                                                                mul(mload(add(state, 192)), 13)
                                                            ),
                                                            mul(mload(add(state, 224)), 3)
                                                        ),
                                                        mload(add(state, 256))
                                                    ),
                                                    mload(add(state, 288))
                                                ),
                                                mul(mload(add(state, 320)), 51)
                                            ),
                                            mload(add(state, 352))
                                        ),
                                        mul(mload(add(state, 384)), 11)
                                    ),
                                    mul(mload(add(state, 416)), 17)
                                ),
                                mul(mload(add(state, 448)), 2)
                            ),
                            mload(add(state, 480))
                        ),
                        p
                    )
                )
                mstore(
                    add(scratch, 288),
                    mod(
                        add(
                            add(
                                add(
                                    add(
                                        add(
                                            add(
                                                add(
                                                    add(
                                                        add(
                                                            add(
                                                                add(
                                                                    add(
                                                                        add(
                                                                            add(
                                                                                add(
                                                                                    mload(add(state, 0)),
                                                                                    mul(mload(add(state, 32)), 101)
                                                                                ),
                                                                                mul(mload(add(state, 64)), 63)
                                                                            ),
                                                                            mul(mload(add(state, 96)), 15)
                                                                        ),
                                                                        mul(mload(add(state, 128)), 2)
                                                                    ),
                                                                    mul(mload(add(state, 160)), 67)
                                                                ),
                                                                mul(mload(add(state, 192)), 22)
                                                            ),
                                                            mul(mload(add(state, 224)), 13)
                                                        ),
                                                        mul(mload(add(state, 256)), 3)
                                                    ),
                                                    mload(add(state, 288))
                                                ),
                                                mload(add(state, 320))
                                            ),
                                            mul(mload(add(state, 352)), 51)
                                        ),
                                        mload(add(state, 384))
                                    ),
                                    mul(mload(add(state, 416)), 11)
                                ),
                                mul(mload(add(state, 448)), 17)
                            ),
                            mul(mload(add(state, 480)), 2)
                        ),
                        p
                    )
                )
                mstore(
                    add(scratch, 320),
                    mod(
                        add(
                            add(
                                add(
                                    add(
                                        add(
                                            add(
                                                add(
                                                    add(
                                                        add(
                                                            add(
                                                                add(
                                                                    add(
                                                                        add(
                                                                            add(
                                                                                add(
                                                                                    mul(mload(add(state, 0)), 2),
                                                                                    mload(add(state, 32))
                                                                                ),
                                                                                mul(mload(add(state, 64)), 101)
                                                                            ),
                                                                            mul(mload(add(state, 96)), 63)
                                                                        ),
                                                                        mul(mload(add(state, 128)), 15)
                                                                    ),
                                                                    mul(mload(add(state, 160)), 2)
                                                                ),
                                                                mul(mload(add(state, 192)), 67)
                                                            ),
                                                            mul(mload(add(state, 224)), 22)
                                                        ),
                                                        mul(mload(add(state, 256)), 13)
                                                    ),
                                                    mul(mload(add(state, 288)), 3)
                                                ),
                                                mload(add(state, 320))
                                            ),
                                            mload(add(state, 352))
                                        ),
                                        mul(mload(add(state, 384)), 51)
                                    ),
                                    mload(add(state, 416))
                                ),
                                mul(mload(add(state, 448)), 11)
                            ),
                            mul(mload(add(state, 480)), 17)
                        ),
                        p
                    )
                )
                mstore(
                    add(scratch, 352),
                    mod(
                        add(
                            add(
                                add(
                                    add(
                                        add(
                                            add(
                                                add(
                                                    add(
                                                        add(
                                                            add(
                                                                add(
                                                                    add(
                                                                        add(
                                                                            add(
                                                                                add(
                                                                                    mul(mload(add(state, 0)), 17),
                                                                                    mul(mload(add(state, 32)), 2)
                                                                                ),
                                                                                mload(add(state, 64))
                                                                            ),
                                                                            mul(mload(add(state, 96)), 101)
                                                                        ),
                                                                        mul(mload(add(state, 128)), 63)
                                                                    ),
                                                                    mul(mload(add(state, 160)), 15)
                                                                ),
                                                                mul(mload(add(state, 192)), 2)
                                                            ),
                                                            mul(mload(add(state, 224)), 67)
                                                        ),
                                                        mul(mload(add(state, 256)), 22)
                                                    ),
                                                    mul(mload(add(state, 288)), 13)
                                                ),
                                                mul(mload(add(state, 320)), 3)
                                            ),
                                            mload(add(state, 352))
                                        ),
                                        mload(add(state, 384))
                                    ),
                                    mul(mload(add(state, 416)), 51)
                                ),
                                mload(add(state, 448))
                            ),
                            mul(mload(add(state, 480)), 11)
                        ),
                        p
                    )
                )
                mstore(
                    add(scratch, 384),
                    mod(
                        add(
                            add(
                                add(
                                    add(
                                        add(
                                            add(
                                                add(
                                                    add(
                                                        add(
                                                            add(
                                                                add(
                                                                    add(
                                                                        add(
                                                                            add(
                                                                                add(
                                                                                    mul(mload(add(state, 0)), 11),
                                                                                    mul(mload(add(state, 32)), 17)
                                                                                ),
                                                                                mul(mload(add(state, 64)), 2)
                                                                            ),
                                                                            mload(add(state, 96))
                                                                        ),
                                                                        mul(mload(add(state, 128)), 101)
                                                                    ),
                                                                    mul(mload(add(state, 160)), 63)
                                                                ),
                                                                mul(mload(add(state, 192)), 15)
                                                            ),
                                                            mul(mload(add(state, 224)), 2)
                                                        ),
                                                        mul(mload(add(state, 256)), 67)
                                                    ),
                                                    mul(mload(add(state, 288)), 22)
                                                ),
                                                mul(mload(add(state, 320)), 13)
                                            ),
                                            mul(mload(add(state, 352)), 3)
                                        ),
                                        mload(add(state, 384))
                                    ),
                                    mload(add(state, 416))
                                ),
                                mul(mload(add(state, 448)), 51)
                            ),
                            mload(add(state, 480))
                        ),
                        p
                    )
                )
                mstore(
                    add(scratch, 416),
                    mod(
                        add(
                            add(
                                add(
                                    add(
                                        add(
                                            add(
                                                add(
                                                    add(
                                                        add(
                                                            add(
                                                                add(
                                                                    add(
                                                                        add(
                                                                            add(
                                                                                add(
                                                                                    mload(add(state, 0)),
                                                                                    mul(mload(add(state, 32)), 11)
                                                                                ),
                                                                                mul(mload(add(state, 64)), 17)
                                                                            ),
                                                                            mul(mload(add(state, 96)), 2)
                                                                        ),
                                                                        mload(add(state, 128))
                                                                    ),
                                                                    mul(mload(add(state, 160)), 101)
                                                                ),
                                                                mul(mload(add(state, 192)), 63)
                                                            ),
                                                            mul(mload(add(state, 224)), 15)
                                                        ),
                                                        mul(mload(add(state, 256)), 2)
                                                    ),
                                                    mul(mload(add(state, 288)), 67)
                                                ),
                                                mul(mload(add(state, 320)), 22)
                                            ),
                                            mul(mload(add(state, 352)), 13)
                                        ),
                                        mul(mload(add(state, 384)), 3)
                                    ),
                                    mload(add(state, 416))
                                ),
                                mload(add(state, 448))
                            ),
                            mul(mload(add(state, 480)), 51)
                        ),
                        p
                    )
                )
                mstore(
                    add(scratch, 448),
                    mod(
                        add(
                            add(
                                add(
                                    add(
                                        add(
                                            add(
                                                add(
                                                    add(
                                                        add(
                                                            add(
                                                                add(
                                                                    add(
                                                                        add(
                                                                            add(
                                                                                add(
                                                                                    mul(mload(add(state, 0)), 51),
                                                                                    mload(add(state, 32))
                                                                                ),
                                                                                mul(mload(add(state, 64)), 11)
                                                                            ),
                                                                            mul(mload(add(state, 96)), 17)
                                                                        ),
                                                                        mul(mload(add(state, 128)), 2)
                                                                    ),
                                                                    mload(add(state, 160))
                                                                ),
                                                                mul(mload(add(state, 192)), 101)
                                                            ),
                                                            mul(mload(add(state, 224)), 63)
                                                        ),
                                                        mul(mload(add(state, 256)), 15)
                                                    ),
                                                    mul(mload(add(state, 288)), 2)
                                                ),
                                                mul(mload(add(state, 320)), 67)
                                            ),
                                            mul(mload(add(state, 352)), 22)
                                        ),
                                        mul(mload(add(state, 384)), 13)
                                    ),
                                    mul(mload(add(state, 416)), 3)
                                ),
                                mload(add(state, 448))
                            ),
                            mload(add(state, 480))
                        ),
                        p
                    )
                )
                mstore(
                    add(scratch, 480),
                    mod(
                        add(
                            add(
                                add(
                                    add(
                                        add(
                                            add(
                                                add(
                                                    add(
                                                        add(
                                                            add(
                                                                add(
                                                                    add(
                                                                        add(
                                                                            add(
                                                                                add(
                                                                                    mload(add(state, 0)),
                                                                                    mul(mload(add(state, 32)), 51)
                                                                                ),
                                                                                mload(add(state, 64))
                                                                            ),
                                                                            mul(mload(add(state, 96)), 11)
                                                                        ),
                                                                        mul(mload(add(state, 128)), 17)
                                                                    ),
                                                                    mul(mload(add(state, 160)), 2)
                                                                ),
                                                                mload(add(state, 192))
                                                            ),
                                                            mul(mload(add(state, 224)), 101)
                                                        ),
                                                        mul(mload(add(state, 256)), 63)
                                                    ),
                                                    mul(mload(add(state, 288)), 15)
                                                ),
                                                mul(mload(add(state, 320)), 2)
                                            ),
                                            mul(mload(add(state, 352)), 67)
                                        ),
                                        mul(mload(add(state, 384)), 22)
                                    ),
                                    mul(mload(add(state, 416)), 13)
                                ),
                                mul(mload(add(state, 448)), 3)
                            ),
                            mload(add(state, 480))
                        ),
                        p
                    )
                )
                for { let i := 0 } lt(i, 512) { i := add(i, 32) } {
                    mstore(add(state, i), mload(add(scratch, i)))
                }
            }
        }
    }

    function compress(uint256[8] memory left, uint256[8] memory right)
        internal
        pure
        returns (uint256[8] memory result)
    {
        uint256[16] memory state;
        for (uint256 i = 0; i < 8; ++i) {
            state[i] = left[i];
            state[i + 8] = right[i];
        }
        permute(state);
        for (uint256 i = 0; i < 8; ++i) {
            result[i] = state[i];
        }
    }

    function hashWords(uint256[] memory values) internal pure returns (uint256[8] memory result) {
        if (values.length == 0 || values.length % 8 != 0) revert InvalidLeafLength();
        uint256[16] memory state;
        state[0] = values.length;
        for (uint256 offset = 0; offset < values.length; offset += 8) {
            for (uint256 i = 0; i < 8; ++i) {
                uint256 value = values[offset + i];
                if (value >= MODULUS) revert NonCanonicalField();
                state[i + 8] = value;
            }
            permute(state);
        }
        for (uint256 i = 0; i < 8; ++i) {
            result[i] = state[i + 8];
        }
    }

    function hashLeaf(uint256[] memory values) internal pure returns (uint256[8] memory result) {
        if (values.length == 0 || values.length % 8 != 0) revert InvalidLeafLength();
        uint256[16] memory state;
        state[0] = values.length;
        for (uint256 offset = values.length; offset != 0; offset -= 8) {
            for (uint256 i = 0; i < 8; ++i) {
                uint256 value = values[offset - 8 + i];
                if (value >= MODULUS) revert NonCanonicalField();
                state[i + 8] = value;
            }
            permute(state);
        }
        for (uint256 i = 0; i < 8; ++i) {
            result[i] = state[i + 8];
        }
    }
}
