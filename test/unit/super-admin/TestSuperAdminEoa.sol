// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Constants } from "../../data/Constants.sol";
import { Helpers } from "../../helpers/Helpers.t.sol";
import { Errors } from "../../../contracts/type/Errors.sol";
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

        _mint(address(paymaster), Constants.ERC20_MINT_VAL_100_18, true);
    }

    // ------------------------------------------------------------------------------------
    //
    //                       function authorizeAdmin(Key memory _key)
    //
    // ------------------------------------------------------------------------------------

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

    function test_super_admin_eoa_authorize_admin_aa_mode_00() external {
        random = _createKeySecp256k1(TypeOfKey.ADMIN, randomEoa);
        expected.push(random);

        bytes memory data = abi.encodeWithSelector(paymaster.authorizeAdmin.selector, random);
        (PackedUserOperation[] memory u, bytes32 hash) = _getUserOp(
            address(paymaster),
            __PAYMASTER_SUPER_ADMIN_EOA,
            data,
            Sponsor_Type.ETH,
            Allow_Bundlers.ALL,
            SignerType.Secp256k1
        );

        u[0].signature = _packEoaSigner(__PAYMASTER_SUPER_ADMIN_EOA, hash);

        _relayUserOp(u);
        _assert(expected);
    }

    function test_super_admin_eoa_authorize_admin_aa_mode_01() external {
        random = _createKeySecp256k1(TypeOfKey.ADMIN, randomEoa);
        expected.push(random);

        bytes memory dataApprove =
            abi.encodeWithSelector(IERC20.approve.selector, address(paymaster), type(uint256).max);
        bytes memory dataAuthorizeAdmin = abi.encodeWithSelector(paymaster.authorizeAdmin.selector, random);

        calls.push(_encodeCall(address(sponsorERC20), 0, dataApprove));
        calls.push(_encodeCall(address(paymaster), 0, dataAuthorizeAdmin));

        bytes memory data = abi.encodeWithSelector(paymaster.executeBatch.selector, calls);

        (PackedUserOperation[] memory u, bytes32 hash) = _getUserOp(
            address(paymaster),
            __PAYMASTER_SUPER_ADMIN_EOA,
            data,
            Sponsor_Type.ERC20,
            Allow_Bundlers.ALL,
            SignerType.Secp256k1
        );

        u[0].signature = _packEoaSigner(__PAYMASTER_SUPER_ADMIN_EOA, hash);

        _relayUserOp(u);
        _assert(expected);
    }

    // ------------------------------------------------------------------------------------
    //
    //                            function revoke(bytes32 _keyHash)
    //
    // ------------------------------------------------------------------------------------

    function test_super_admin_eoa_revoke_admin_direct() external {
        random = _createKeySecp256k1(TypeOfKey.ADMIN, randomEoa);
        expected.push(random);

        vm.prank(__PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);
        paymaster.authorizeAdmin(random);

        _assert(expected);

        vm.prank(__PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);
        paymaster.revoke(random.hash());

        _assertRevoked(random);
    }

    function test_super_admin_eoa_revoke_admin_aa_mode_00() external {
        random = _createKeySecp256k1(TypeOfKey.ADMIN, randomEoa);
        expected.push(random);

        bytes memory data = abi.encodeWithSelector(paymaster.authorizeAdmin.selector, random);

        (PackedUserOperation[] memory u, bytes32 hash) = _getUserOp(
            address(paymaster),
            __PAYMASTER_SUPER_ADMIN_EOA,
            data,
            Sponsor_Type.ETH,
            Allow_Bundlers.ALL,
            SignerType.Secp256k1
        );

        u[0].signature = _packEoaSigner(__PAYMASTER_SUPER_ADMIN_EOA, hash);

        _relayUserOp(u);
        _assert(expected);

        data = abi.encodeWithSelector(paymaster.revoke.selector, random.hash());

        (u, hash) = _getUserOp(
            address(paymaster),
            __PAYMASTER_SUPER_ADMIN_EOA,
            data,
            Sponsor_Type.ETH,
            Allow_Bundlers.ALL,
            SignerType.Secp256k1
        );

        u[0].signature = _packEoaSigner(__PAYMASTER_SUPER_ADMIN_EOA, hash);

        _relayUserOp(u);

        _assertRevoked(random);
    }

    function test_super_admin_eoa_revoke_admin_aa_mode_01() external {
        random = _createKeySecp256k1(TypeOfKey.ADMIN, randomEoa);
        expected.push(random);

        bytes memory dataApprove =
            abi.encodeWithSelector(IERC20.approve.selector, address(paymaster), type(uint256).max);
        bytes memory dataAuthorizeAdmin = abi.encodeWithSelector(paymaster.authorizeAdmin.selector, random);

        calls.push(_encodeCall(address(sponsorERC20), 0, dataApprove));
        calls.push(_encodeCall(address(paymaster), 0, dataAuthorizeAdmin));

        bytes memory data = abi.encodeWithSelector(paymaster.executeBatch.selector, calls);

        (PackedUserOperation[] memory u, bytes32 hash) = _getUserOp(
            address(paymaster),
            __PAYMASTER_SUPER_ADMIN_EOA,
            data,
            Sponsor_Type.ERC20,
            Allow_Bundlers.ALL,
            SignerType.Secp256k1
        );

        u[0].signature = _packEoaSigner(__PAYMASTER_SUPER_ADMIN_EOA, hash);

        _relayUserOp(u);
        _assert(expected);

        data = abi.encodeWithSelector(paymaster.revoke.selector, random.hash());

        (u, hash) = _getUserOp(
            address(paymaster),
            __PAYMASTER_SUPER_ADMIN_EOA,
            data,
            Sponsor_Type.ERC20,
            Allow_Bundlers.ALL,
            SignerType.Secp256k1
        );

        u[0].signature = _packEoaSigner(__PAYMASTER_SUPER_ADMIN_EOA, hash);

        _relayUserOp(u);
    }

    // ------------------------------------------------------------------------------------
    //
    //                       function addSigner(Key calldata _signer)
    //
    // ------------------------------------------------------------------------------------

    function test_super_admin_eoa_add_signer_direct() external {
        random = _createKeySecp256k1(TypeOfKey.SIGNER, randomEoa);
        expected.push(random);

        vm.prank(__PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);
        paymaster.addSigner(random);
        _assert(expected);
    }

    function test_super_admin_eoa_add_signer_aa_mode_00() external {
        random = _createKeySecp256k1(TypeOfKey.SIGNER, randomEoa);
        expected.push(random);

        bytes memory data = abi.encodeWithSelector(paymaster.addSigner.selector, random);

        (PackedUserOperation[] memory u, bytes32 hash) = _getUserOp(
            address(paymaster),
            __PAYMASTER_SUPER_ADMIN_EOA,
            data,
            Sponsor_Type.ETH,
            Allow_Bundlers.ALL,
            SignerType.Secp256k1
        );

        u[0].signature = _packEoaSigner(__PAYMASTER_SUPER_ADMIN_EOA, hash);

        _relayUserOp(u);
        _assert(expected);
    }

    function test_super_admin_eoa_add_signer_aa_mode_01() external {
        // ADMIN cant execute executeBatch() function need to see what in this edge case to do
        random = _createKeySecp256k1(TypeOfKey.SIGNER, randomEoa);
        expected.push(random);

        bytes memory dataApprove =
            abi.encodeWithSelector(IERC20.approve.selector, address(paymaster), type(uint256).max);
        bytes memory dataAuthorizeAdmin = abi.encodeWithSelector(paymaster.addSigner.selector, random);

        calls.push(_encodeCall(address(sponsorERC20), 0, dataApprove));
        calls.push(_encodeCall(address(paymaster), 0, dataAuthorizeAdmin));

        bytes memory data = abi.encodeWithSelector(paymaster.executeBatch.selector, calls);

        (PackedUserOperation[] memory u, bytes32 hash) = _getUserOp(
            address(paymaster),
            __PAYMASTER_SUPER_ADMIN_EOA,
            data,
            Sponsor_Type.ERC20,
            Allow_Bundlers.ALL,
            SignerType.Secp256k1
        );

        u[0].signature = _packEoaSigner(__PAYMASTER_SUPER_ADMIN_EOA, hash);

        _relayUserOp(u);
        _assert(expected);
    }

    // ------------------------------------------------------------------------------------
    //
    //                            removeSigner(bytes32 _signer)
    //
    // ------------------------------------------------------------------------------------

    function test_super_admin_eoa_remove_signer_direct() external {
        _addSigner();
        vm.prank(__PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);
        paymaster.removeSigner(random.hash());

        _assertRevoked(random);
    }

    function test_super_admin_eoa_remove_signer_aa_mode_00() external {
        _addSigner();

        bytes memory data = abi.encodeWithSelector(paymaster.removeSigner.selector, random.hash());

        (PackedUserOperation[] memory u, bytes32 hash) = _getUserOp(
            address(paymaster),
            __PAYMASTER_SUPER_ADMIN_EOA,
            data,
            Sponsor_Type.ETH,
            Allow_Bundlers.ALL,
            SignerType.Secp256k1
        );

        u[0].signature = _packEoaSigner(__PAYMASTER_SUPER_ADMIN_EOA, hash);

        _relayUserOp(u);
        _assertRevoked(random);
    }

    function test_super_admin_eoa_remove_signer_aa_mode_01() external {
        // ADMIN cant execute executeBatch() function need to see what in this edge case to do
        _addSigner();

        bytes memory dataApprove =
            abi.encodeWithSelector(IERC20.approve.selector, address(paymaster), type(uint256).max);
        bytes memory dataAuthorizeAdmin = abi.encodeWithSelector(paymaster.removeSigner.selector, random.hash());

        calls.push(_encodeCall(address(sponsorERC20), 0, dataApprove));
        calls.push(_encodeCall(address(paymaster), 0, dataAuthorizeAdmin));

        bytes memory data = abi.encodeWithSelector(paymaster.executeBatch.selector, calls);

        (PackedUserOperation[] memory u, bytes32 hash) = _getUserOp(
            address(paymaster),
            __PAYMASTER_SUPER_ADMIN_EOA,
            data,
            Sponsor_Type.ERC20,
            Allow_Bundlers.ALL,
            SignerType.Secp256k1
        );

        u[0].signature = _packEoaSigner(__PAYMASTER_SUPER_ADMIN_EOA, hash);

        _relayUserOp(u);
        _assertRevoked(random);
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

    function _addSigner() internal {
        random = _createKeySecp256k1(TypeOfKey.SIGNER, randomEoa);
        expected.push(random);

        vm.prank(__PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);
        paymaster.addSigner(random);
        _assert(expected);
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

    function _assertRevoked(Key memory _k) internal {
        vm.expectRevert(Errors.KeyDoesNotExist.selector);
        paymaster.getKey(_k.hash());
    }
}
