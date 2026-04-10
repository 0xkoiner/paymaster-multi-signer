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
import { IStakeManager } from "lib/account-abstraction-v9/contracts/interfaces/IStakeManager.sol";
import { IERC20 } from "../../../lib/openzeppelin-contracts-v5.5.0/contracts/token/ERC20/IERC20.sol";
import { _parseValidationData, ValidationData } from "lib/account-abstraction-v9/contracts/core/Helpers.sol";
import { PackedUserOperation } from "lib/account-abstraction-v9/contracts/interfaces/PackedUserOperation.sol";

contract TestAdminWebAuthn is Helpers {
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
    P256PubKey internal p256PubKey;

    address internal randomEoa;

    Call[] internal calls;

    function setUp() public override {
        super.setUp();

        randomEoa = makeAddr("random");

        p256PubKey = _fetchWebAuthnSigner(Constants.WEB_AUTHN_JSON_PATH, Constants.SUPER_ADMIN_KEY);
        superAdmin = _createKeySecp256k1(TypeOfKey.SUPER_ADMIN, __PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);
        admin = _createKeyWebAuthn(TypeOfKey.ADMIN, p256PubKey.qx, p256PubKey.qy);
        signer = _createKeySecp256k1(TypeOfKey.SIGNER, __PAYMASTER_SIGNER_ADDRESS_EOA);

        expected.push(superAdmin);
        expected.push(admin);
        expected.push(signer);

        _createBundlers(keccak256("bundlers-2"), 2);

        _ethc();
        _deployment();

        _deal(__7702_ADDRESS_EOA, Constants.ETH_1);
        _deal(address(paymaster), Constants.ETH_1);

        IEntryPoint(Constants.EP_V9_ADDRESS).depositTo{ value: Constants.ETH_0_1 }(address(paymaster));

        _mint(address(paymaster), Constants.ERC20_MINT_VAL_100_18, true);
    }
    // ------------------------------------------------------------------------------------
    //
    //                       function addSigner(Key calldata _signer)
    //
    // ------------------------------------------------------------------------------------

    function test_admin_webauthn_add_signer_aa_mode_00() external {
        random = _createKeySecp256k1(TypeOfKey.SIGNER, randomEoa);
        expected.push(random);

        bytes memory data = abi.encodeWithSelector(paymaster.addSigner.selector, random);

        (PackedUserOperation[] memory u, bytes32 hash) = _getUserOp(
            address(paymaster), __PAYMASTER_ADMIN_EOA, data, Sponsor_Type.ETH, Allow_Bundlers.ALL, SignerType.Secp256k1
        );

        u[0].signature = _packWebAuthnSigner(hash);

        _relayUserOp(u);
        _assert(expected);
    }

    function test_admin_webauthn_add_signer_aa_mode_01() external {
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
            __PAYMASTER_ADMIN_EOA,
            data,
            Sponsor_Type.ERC20,
            Allow_Bundlers.ALL,
            SignerType.Secp256k1
        );

        u[0].signature = _packWebAuthnSigner(hash);

        _relayUserOp(u);
        _assert(expected);
    }

    // ------------------------------------------------------------------------------------
    //
    //                                    function deposit()
    //
    // ------------------------------------------------------------------------------------

    function test_admin_webauthn_deposit_aa_mode_00() external {
        calls.push(_encodeCall(address(paymaster), 0.1 ether, abi.encodeWithSelector(paymaster.deposit.selector)));
        bytes memory data = abi.encodeWithSelector(paymaster.executeBatch.selector, calls);

        (PackedUserOperation[] memory u, bytes32 hash) = _getUserOp(
            address(paymaster), __PAYMASTER_ADMIN_EOA, data, Sponsor_Type.ETH, Allow_Bundlers.ALL, SignerType.Secp256k1
        );

        u[0].signature = _packWebAuthnSigner(hash);

        _relayUserOp(u);
        _assertDeposit();
    }

    function test_admin_webauthn_deposit_aa_mode_01() external {
        bytes memory dataApprove =
            abi.encodeWithSelector(IERC20.approve.selector, address(paymaster), type(uint256).max);

        calls.push(_encodeCall(address(sponsorERC20), 0, dataApprove));
        calls.push(_encodeCall(address(paymaster), 0.1 ether, abi.encodeWithSelector(paymaster.deposit.selector)));

        bytes memory data = abi.encodeWithSelector(paymaster.executeBatch.selector, calls);

        (PackedUserOperation[] memory u, bytes32 hash) = _getUserOp(
            address(paymaster),
            __PAYMASTER_ADMIN_EOA,
            data,
            Sponsor_Type.ERC20,
            Allow_Bundlers.ALL,
            SignerType.Secp256k1
        );

        u[0].signature = _packWebAuthnSigner(hash);

        _relayUserOp(u);
        _assertDeposit();
    }

    // ------------------------------------------------------------------------------------
    //
    //                                    function addStake()
    //
    // ------------------------------------------------------------------------------------

    function test_admin_webauthn_add_stake_aa_mode_00() external {
        calls.push(
            _encodeCall(
                address(paymaster),
                Constants.ETH_0_1,
                abi.encodeWithSelector(paymaster.addStake.selector, Constants.UNSTAKE_DELAY)
            )
        );
        bytes memory data = abi.encodeWithSelector(paymaster.executeBatch.selector, calls);

        (PackedUserOperation[] memory u, bytes32 hash) = _getUserOp(
            address(paymaster), __PAYMASTER_ADMIN_EOA, data, Sponsor_Type.ETH, Allow_Bundlers.ALL, SignerType.Secp256k1
        );

        u[0].signature = _packWebAuthnSigner(hash);

        _relayUserOp(u);
        _assertStaked();
    }

    function test_admin_webauthn_add_stake_aa_mode_01() external {
        bytes memory dataApprove =
            abi.encodeWithSelector(IERC20.approve.selector, address(paymaster), type(uint256).max);

        calls.push(_encodeCall(address(sponsorERC20), 0, dataApprove));
        calls.push(
            _encodeCall(
                address(paymaster),
                Constants.ETH_0_1,
                abi.encodeWithSelector(paymaster.addStake.selector, Constants.UNSTAKE_DELAY)
            )
        );

        bytes memory data = abi.encodeWithSelector(paymaster.executeBatch.selector, calls);

        (PackedUserOperation[] memory u, bytes32 hash) = _getUserOp(
            address(paymaster),
            __PAYMASTER_ADMIN_EOA,
            data,
            Sponsor_Type.ERC20,
            Allow_Bundlers.ALL,
            SignerType.Secp256k1
        );

        u[0].signature = _packWebAuthnSigner(hash);

        _relayUserOp(u);
        _assertStaked();
    }

    // ------------------------------------------------------------------------------------
    //
    //                                    function unlockStake()
    //
    // ------------------------------------------------------------------------------------

    function test_admin_webauthn_unlock_stake_aa_mode_00() external {
        _stake();
        _assertStaked();

        bytes memory data = abi.encodeWithSelector(paymaster.unlockStake.selector);

        (PackedUserOperation[] memory u, bytes32 hash) = _getUserOp(
            address(paymaster), __PAYMASTER_ADMIN_EOA, data, Sponsor_Type.ETH, Allow_Bundlers.ALL, SignerType.Secp256k1
        );

        u[0].signature = _packWebAuthnSigner(hash);

        _relayUserOp(u);
        _assertUnlocked();
    }

    function test_admin_webauthn_unlock_stake_aa_mode_01() external {
        _stake();
        _assertStaked();

        bytes memory dataApprove =
            abi.encodeWithSelector(IERC20.approve.selector, address(paymaster), type(uint256).max);
        bytes memory dataUnlockStake = abi.encodeWithSelector(paymaster.unlockStake.selector);

        calls.push(_encodeCall(address(sponsorERC20), 0, dataApprove));
        calls.push(_encodeCall(address(paymaster), 0, dataUnlockStake));

        bytes memory data = abi.encodeWithSelector(paymaster.executeBatch.selector, calls);

        (PackedUserOperation[] memory u, bytes32 hash) = _getUserOp(
            address(paymaster),
            __PAYMASTER_ADMIN_EOA,
            data,
            Sponsor_Type.ERC20,
            Allow_Bundlers.ALL,
            SignerType.Secp256k1
        );

        u[0].signature = _packWebAuthnSigner(hash);

        _relayUserOp(u);
        _assertUnlocked();
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

        bytes memory data = abi.encodeWithSelector(paymaster.addSigner.selector, random);

        (PackedUserOperation[] memory u, bytes32 hash) = _getUserOp(
            address(paymaster),
            __PAYMASTER_SUPER_ADMIN_EOA,
            data,
            Sponsor_Type.ETH,
            Allow_Bundlers.ALL,
            SignerType.Secp256k1
        );

        u[0].signature = _packWebAuthnSigner(hash);

        _relayUserOp(u);
        _assert(expected);
    }

    function _deposit() internal {
        delete calls;
        bytes memory dataApprove =
            abi.encodeWithSelector(IERC20.approve.selector, address(paymaster), type(uint256).max);

        calls.push(_encodeCall(address(sponsorERC20), 0, dataApprove));
        calls.push(_encodeCall(address(paymaster), 0.1 ether, abi.encodeWithSelector(paymaster.deposit.selector)));

        bytes memory data = abi.encodeWithSelector(paymaster.executeBatch.selector, calls);

        (PackedUserOperation[] memory u, bytes32 hash) = _getUserOp(
            address(paymaster),
            __PAYMASTER_SUPER_ADMIN_EOA,
            data,
            Sponsor_Type.ERC20,
            Allow_Bundlers.ALL,
            SignerType.Secp256k1
        );

        u[0].signature = _packWebAuthnSigner(hash);

        _relayUserOp(u);
        _assertDeposit();
        delete calls;
    }

    function _stake() internal {
        delete calls;
        calls.push(
            _encodeCall(
                address(paymaster),
                Constants.ETH_0_1,
                abi.encodeWithSelector(paymaster.addStake.selector, Constants.UNSTAKE_DELAY)
            )
        );
        bytes memory data = abi.encodeWithSelector(paymaster.executeBatch.selector, calls);

        (PackedUserOperation[] memory u, bytes32 hash) = _getUserOp(
            address(paymaster),
            __PAYMASTER_SUPER_ADMIN_EOA,
            data,
            Sponsor_Type.ETH,
            Allow_Bundlers.ALL,
            SignerType.Secp256k1
        );

        u[0].signature = _packWebAuthnSigner(hash);

        _relayUserOp(u);
        _assertStaked();
        delete calls;
    }

    function _unlockStake() internal {
        bytes memory data = abi.encodeWithSelector(paymaster.unlockStake.selector);

        (PackedUserOperation[] memory u, bytes32 hash) = _getUserOp(
            address(paymaster),
            __PAYMASTER_SUPER_ADMIN_EOA,
            data,
            Sponsor_Type.ETH,
            Allow_Bundlers.ALL,
            SignerType.Secp256k1
        );

        u[0].signature = _packWebAuthnSigner(hash);

        _relayUserOp(u);
        _assertUnlocked();
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

    function _assertDeposit() internal view {
        (IStakeManager.DepositInfo memory info) = IEntryPoint(address(entryPoint)).getDepositInfo(address(paymaster));
        assertApproxEqRel(info.deposit, (Constants.ETH_0_1 * 2), 0.01e18, "Not same deposit");
        assertFalse(info.staked, "Not same staked");
        assertEq(info.stake, 0, "Not same stake");
        assertEq(info.unstakeDelaySec, 0, "Not same unstakeDelaySec");
        assertEq(info.withdrawTime, 0, "Not same withdrawTime");
    }

    function _assertStaked() internal view {
        (IStakeManager.DepositInfo memory info) = IEntryPoint(address(entryPoint)).getDepositInfo(address(paymaster));
        assertTrue(info.staked, "Not staked");
        assertEq(info.stake, Constants.ETH_0_1, "Not same stake");
        assertEq(info.unstakeDelaySec, Constants.UNSTAKE_DELAY, "Not same unstakeDelaySec");
        assertEq(info.withdrawTime, 0, "Not same withdrawTime");
    }

    function _assertUnlocked() internal view {
        (IStakeManager.DepositInfo memory info) = IEntryPoint(address(entryPoint)).getDepositInfo(address(paymaster));
        assertFalse(info.staked, "Still staked");
        assertEq(info.stake, Constants.ETH_0_1, "Not same stake");
        assertEq(info.unstakeDelaySec, Constants.UNSTAKE_DELAY, "Not same unstakeDelaySec");
        assertGt(info.withdrawTime, 0, "withdrawTime not set");
    }
}
