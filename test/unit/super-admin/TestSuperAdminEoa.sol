// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Constants } from "../../data/Constants.sol";
import { Helpers } from "../../helpers/Helpers.t.sol";
import { KeyLib } from "../../../contracts/library/KeyLib.sol";
import { Key, SignerType } from "../../../contracts/type/Types.sol";
import { ERC20PostOpContext } from "../../../contracts/type/Types.sol";
import { BaseAccount } from "lib/account-abstraction-v9/contracts/core/BaseAccount.sol";
import { IEntryPoint } from "lib/account-abstraction-v9/contracts/interfaces/IEntryPoint.sol";
import { IERC20 } from "../../../lib/openzeppelin-contracts-v5.5.0/contracts/token/ERC20/IERC20.sol";
import { _parseValidationData, ValidationData } from "lib/account-abstraction-v9/contracts/core/Helpers.sol";
import { PackedUserOperation } from "lib/account-abstraction-v9/contracts/interfaces/PackedUserOperation.sol";

contract TestSuperAdminEoa is Helpers {
    using KeyLib for *;

    // ------------------------------------------------------------------------------------
    //
    //                                        Storage
    //
    // ------------------------------------------------------------------------------------

    Key internal superAdmin;
    Key internal admin;
    Key internal signer;
    Key internal random;
    Key[] internal expected;

    address internal randomEoa;

    Call[] internal calls;

    function setUp() public override {
        super.setUp();

        randomEoa = makeAddr("random");

        superAdmin = _createKeySecp256k1(TypeOfKey.SUPER_ADMIN, __PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);
        admin = _createKeySecp256k1(TypeOfKey.ADMIN, __PAYMASTER__ADMIN_ADDRESS_EOA);
        signer = _createKeySecp256k1(TypeOfKey.SIGNER, __PAYMASTER_SIGNER_ADDRESS_EOA);

        expected.push(superAdmin);
        expected.push(admin);
        expected.push(signer);

        _createBundlers(keccak256("bundlers-2"), 2);

        _deployment();

        _deal(__PAYMASTER_SUPER_ADMIN_ADDRESS_EOA, Constants.ETH_1);
        _deal(__7702_ADDRESS_EOA, Constants.ETH_1);
        _depositPaymaster();

        _mint(__7702_ADDRESS_EOA, Constants.ERC20_MINT_VAL_100_18, true);
    }

    function test_super_admin_eoa_authorize_admin_direct() external {
        random = _createKeySecp256k1(TypeOfKey.ADMIN, randomEoa);
        expected.push(random);

        vm.prank(__PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);
        paymaster.authorizeAdmin(random);

        _assert(expected);

        random = _createKeyP256(TypeOfKey.ADMIN);
        expected.push(random);

        vm.prank(__PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);
        paymaster.authorizeAdmin(random);

        _assert(expected);

        random = _createKeyWebAuthn(TypeOfKey.ADMIN);
        expected.push(random);

        vm.prank(__PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);
        paymaster.authorizeAdmin(random);

        _assert(expected);
    }

    function test_super_admin_eoa_authorize_admin_aa_mode_00() external { }

    function test_super_admin_eoa_authorize_admin_aa_mode_01() external { }

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

    // Assert all keys in paymaster storage against expected keys
    function _assert(Key[] memory _expected) internal view {
        uint256 keyCount = paymaster.keyCount();
        (Key[] memory keys, bytes32[] memory hashes) = paymaster.getKeys();

        assertEq(keyCount, _expected.length, "Key count mismatch");

        for (uint256 i = 0; i < _expected.length;) {
            assertEq(keys[i].expiry, _expected[i].expiry, "Not Same expiry");
            assertEq(uint8(keys[i].keyType), uint8(_expected[i].keyType), "Not Same keyType");
            assertEq(keys[i].isSuperAdmin, _expected[i].isSuperAdmin, "Not Same isSuperAdmin");
            assertEq(keys[i].isAdmin, _expected[i].isAdmin, "Not Same isAdmin");
            assertEq(keys[i].publicKey, _expected[i].publicKey, "Not Same publicKey");
            assertEq(hashes[i], _expected[i].hash(), "Not Same keyHash");

            unchecked {
                ++i;
            }
        }
    }
}
