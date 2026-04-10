// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Constants } from "../data/Constants.sol";
import { Helpers } from "../helpers/Helpers.t.sol";
import { KeyLib } from "../../contracts/library/KeyLib.sol";
import { Key, SignerType } from "../../contracts/type/Types.sol";
import { IEntryPoint } from "lib/account-abstraction-v9/contracts/interfaces/IEntryPoint.sol";

contract TestDeployment is Helpers {
    using KeyLib for *;

    // ------------------------------------------------------------------------------------
    //
    //                                        Storage
    //
    // ------------------------------------------------------------------------------------

    Key internal superAdmin;
    Key internal admin;
    Key internal signer;

    function setUp() public override {
        super.setUp();

        superAdmin = _createKeySecp256k1(TypeOfKey.SUPER_ADMIN, __PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);
        admin = _createKeySecp256k1(TypeOfKey.ADMIN, __PAYMASTER__ADMIN_ADDRESS_EOA);
        signer = _createKeySecp256k1(TypeOfKey.SIGNER, __PAYMASTER_SIGNER_ADDRESS_EOA);

        _createBundlers(keccak256("bundlers-2"), 2);

        _deployment();
    }

    // Test full deployment and states
    function test_after_deploy() external view {
        uint256 keyCount = paymaster.keyCount();
        (Key[] memory keys, bytes32[] memory hashes) = paymaster.getKeys();

        assertEq(keyCount, 3);
        _assert(keys[0], superAdmin, hashes[0]);
        _assert(keys[1], admin, hashes[1]);
        _assert(keys[2], signer, hashes[2]);
        _assertBundlers();
    }

    // Test getDeposit returns correct balance
    function test_getDeposit() external {
        vm.deal(__PAYMASTER_SUPER_ADMIN_ADDRESS_EOA, Constants.ETH_1);
        vm.prank(__PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);
        paymaster.deposit{ value: Constants.ETH_0_1 }();

        assertEq(paymaster.getDeposit(), Constants.ETH_0_1, "Not same deposit");
    }

    // Test keyAt returns correct key by index
    function test_keyAt() external view {
        Key memory k0 = paymaster.keyAt(0);
        Key memory k1 = paymaster.keyAt(1);
        Key memory k2 = paymaster.keyAt(2);

        assertEq(k0.publicKey, superAdmin.publicKey, "keyAt(0) publicKey mismatch");
        assertEq(k1.publicKey, admin.publicKey, "keyAt(1) publicKey mismatch");
        assertEq(k2.publicKey, signer.publicKey, "keyAt(2) publicKey mismatch");
    }

    // Test getKey returns correct key by hash
    function test_getKey() external view {
        Key memory k = paymaster.getKey(superAdmin.hash());
        assertEq(k.expiry, superAdmin.expiry, "Not same expiry");
        assertEq(uint8(k.keyType), uint8(superAdmin.keyType), "Not same keyType");
        assertEq(k.isSuperAdmin, superAdmin.isSuperAdmin, "Not same isSuperAdmin");
        assertEq(k.isAdmin, superAdmin.isAdmin, "Not same isAdmin");
        assertEq(k.publicKey, superAdmin.publicKey, "Not same publicKey");
    }

    // Test _expectedPenaltyGasCost calculation
    function test_expectedPenaltyGasCost() external view {
        // actualGas = actualGasCost / feePerGas + postOpGas = 1000000 / 10 + 50000 = 150000
        // executionGasUsed = actualGas - preOpGas = 150000 - 100000 = 50000
        // unusedGas = executionGasLimit - executionGasUsed = 200000 - 50000 = 150000
        // penalty = unusedGas * 10 / 100 = 15000
        // result = penalty * feePerGas = 15000 * 10 = 150000
        uint256 result = paymaster._expectedPenaltyGasCost(
            1_000_000, // actualGasCost
            10, // actualUserOpFeePerGas
            50_000, // postOpGas
            100_000, // preOpGasApproximation
            200_000 // executionGasLimit
        );
        assertEq(result, 150_000, "Penalty gas cost mismatch");
    }

    // ------------------------------------------------------------------------------------
    //
    //                                        Helpers
    //
    // ------------------------------------------------------------------------------------

    // Deploy Paymaster
    function _deployment() internal {
        Key[] memory kS = new Key[](1);
        kS[0] = signer;

        _deploy(superAdmin, admin, kS, IEntryPoint(Constants.EP_V9_ADDRESS), webAuthnVerifier, bundlers);
    }

    // ------------------------------------------------------------------------------------
    //
    //                                        Assertion
    //
    // ------------------------------------------------------------------------------------

    // Assert states (keys, keyhash, entrypoint)
    function _assert(Key memory _k, Key memory _kStorage, bytes32 _keyHash) internal view {
        assertEq(_k.expiry, _kStorage.expiry, "Not Same expiry");
        assertEq(uint8(_k.keyType), uint8(_kStorage.keyType), "Not Same keyType");
        assertEq(_k.isSuperAdmin, _kStorage.isSuperAdmin, "Not Same isSuperAdmin");
        assertEq(_k.isAdmin, _kStorage.isAdmin, "isAdmin");
        assertEq(_k.publicKey, _kStorage.publicKey, "Not Same publicKey");

        assertEq(_keyHash, _kStorage.hash(), "Not Same keyHash");

        assertEq(Constants.EP_V9_ADDRESS, address(paymaster.entryPoint()), "Not Same entryPoint");
    }

    // Assert bundlers list
    function _assertBundlers() internal view {
        for (uint256 i = 0; i < bundlers.length;) {
            assertTrue(paymaster.isBundlerAllowed(bundlers[i]), "The bundler is not allowed");
            unchecked {
                ++i;
            }
        }
    }
}
