// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Constants } from "../data/Constants.sol";
import { Helpers } from "../helpers/Helpers.t.sol";
import { Errors } from "../../contracts/type/Errors.sol";
import { KeyLib } from "../../contracts/library/KeyLib.sol";
import { Key, SignerType, PostOpMode } from "../../contracts/type/Types.sol";
import { IEntryPoint } from "lib/account-abstraction-v9/contracts/interfaces/IEntryPoint.sol";
import { PackedUserOperation } from "lib/account-abstraction-v9/contracts/interfaces/PackedUserOperation.sol";

contract TestRevertsPaymasterValidation is Helpers {
    using KeyLib for *;

    // ------------------------------------------------------------------------------------
    //
    //                                        Storage
    //
    // ------------------------------------------------------------------------------------

    Key internal superAdmin;
    Key internal admin;
    Key internal signer;

    address internal randomEoa;

    function setUp() public override {
        super.setUp();

        randomEoa = makeAddr("random");

        superAdmin = _createKeySecp256k1(TypeOfKey.SUPER_ADMIN, __PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);
        admin = _createKeySecp256k1(TypeOfKey.ADMIN, __PAYMASTER__ADMIN_ADDRESS_EOA);
        signer = _createKeySecp256k1(TypeOfKey.SIGNER, __PAYMASTER_SIGNER_ADDRESS_EOA);

        _createBundlers(keccak256("bundlers-2"), 2);

        _deployment();

        _deal(address(paymaster), Constants.ETH_1);
        _deal(__PAYMASTER_SUPER_ADMIN_ADDRESS_EOA, Constants.ETH_1);

        _depositPaymaster();
    }

    // ------------------------------------------------------------------------------------
    //
    //    function validatePaymasterUserOp — SenderNotEntryPoint
    //
    // ------------------------------------------------------------------------------------

    function test_revert_validatePaymasterUserOp_not_entryPoint() external {
        PackedUserOperation memory u;
        u.sender = randomEoa;

        vm.expectRevert(Errors.SenderNotEntryPoint.selector);
        vm.prank(randomEoa);
        paymaster.validatePaymasterUserOp(u, bytes32(0), 0);
    }

    // ------------------------------------------------------------------------------------
    //
    //    function postOp — SenderNotEntryPoint
    //
    // ------------------------------------------------------------------------------------

    function test_revert_postOp_not_entryPoint() external {
        vm.expectRevert(Errors.SenderNotEntryPoint.selector);
        vm.prank(randomEoa);
        paymaster.postOp(PostOpMode.opSucceeded, hex"", 0, 0);
    }

    // ------------------------------------------------------------------------------------
    //
    //    function validateUserOp — SenderNotEntryPoint
    //
    // ------------------------------------------------------------------------------------

    function test_revert_validateUserOp_not_entryPoint() external {
        PackedUserOperation memory u;
        u.sender = randomEoa;

        vm.expectRevert(Errors.SenderNotEntryPoint.selector);
        vm.prank(randomEoa);
        paymaster.validateUserOp(u, bytes32(0), 0);
    }

    // ------------------------------------------------------------------------------------
    //
    //    PaymasterAndDataLengthInvalid — paymasterAndData too short
    //
    // ------------------------------------------------------------------------------------

    function test_revert_paymaster_data_length_invalid() external {
        PackedUserOperation memory u;
        u.sender = randomEoa;
        // Only paymaster address + gas limits (52 bytes), no mode/config byte
        u.paymasterAndData = abi.encodePacked(address(paymaster), uint128(GAS), uint128(GAS));

        vm.expectRevert(Errors.PaymasterAndDataLengthInvalid.selector);
        vm.prank(Constants.EP_V9_ADDRESS);
        paymaster.validatePaymasterUserOp(u, bytes32(0), 0);
    }

    // ------------------------------------------------------------------------------------
    //
    //    BundlerNotAllowed — bundler not in whitelist
    //
    // ------------------------------------------------------------------------------------

    function test_revert_bundler_not_allowed() external {
        PackedUserOperation memory u;
        u.sender = randomEoa;
        // mode=VERIFYING(0), allowAllBundlers=false → byte = (0 << 1) | 0 = 0x00
        u.paymasterAndData = abi.encodePacked(
            address(paymaster),
            uint128(GAS),
            uint128(GAS),
            uint8(0x00), // mode=VERIFYING, allowAllBundlers=false
            type(uint48).max,
            uint48(0), // validUntil, validAfter
            uint8(2), // signerType = Secp256k1
            new bytes(65) // dummy signature
        );

        vm.expectRevert(abi.encodeWithSelector(Errors.BundlerNotAllowed.selector, randomEoa));
        vm.prank(Constants.EP_V9_ADDRESS, randomEoa); // msg.sender=EP, tx.origin=randomEoa
        paymaster.validatePaymasterUserOp(u, bytes32(0), 0);
    }

    // ------------------------------------------------------------------------------------
    //
    //    PaymasterModeInvalid — invalid mode byte
    //
    // ------------------------------------------------------------------------------------

    function test_revert_paymaster_mode_invalid() external {
        PackedUserOperation memory u;
        u.sender = randomEoa;
        // mode=2 (invalid), allowAllBundlers=true → byte = (2 << 1) | 1 = 0x05
        u.paymasterAndData = abi.encodePacked(
            address(paymaster),
            uint128(GAS),
            uint128(GAS),
            uint8(0x05), // mode=2 (INVALID), allowAllBundlers=true
            new bytes(120) // enough config bytes
        );

        vm.expectRevert(Errors.PaymasterModeInvalid.selector);
        vm.prank(Constants.EP_V9_ADDRESS);
        paymaster.validatePaymasterUserOp(u, bytes32(0), 0);
    }

    // ------------------------------------------------------------------------------------
    //
    //    PaymasterConfigLengthInvalid — verifying config too short
    //
    // ------------------------------------------------------------------------------------

    function test_revert_verifying_config_length_invalid() external {
        PackedUserOperation memory u;
        u.sender = randomEoa;
        // mode=VERIFYING(0), allowAll=true → byte = (0 << 1) | 1 = 0x01
        u.paymasterAndData = abi.encodePacked(
            address(paymaster),
            uint128(GAS),
            uint128(GAS),
            uint8(0x01), // mode=VERIFYING, allowAllBundlers=true
            new bytes(5) // too short (needs >= 12 for verifying config)
        );

        vm.expectRevert(Errors.PaymasterConfigLengthInvalid.selector);
        vm.prank(Constants.EP_V9_ADDRESS);
        paymaster.validatePaymasterUserOp(u, bytes32(0), 0);
    }

    // ------------------------------------------------------------------------------------
    //
    //    IncorrectSignerType — verifying mode, signerType > 2
    //
    // ------------------------------------------------------------------------------------

    function test_revert_incorrect_signer_type_verifying() external {
        PackedUserOperation memory u;
        u.sender = randomEoa;
        u.paymasterAndData = abi.encodePacked(
            address(paymaster),
            uint128(GAS),
            uint128(GAS),
            uint8(0x01), // mode=VERIFYING, allowAllBundlers=true
            type(uint48).max,
            uint48(0), // validUntil, validAfter
            uint8(3), // signerType = 3 (INVALID)
            new bytes(65) // dummy signature
        );

        vm.expectRevert(Errors.IncorrectSignerType.selector);
        vm.prank(Constants.EP_V9_ADDRESS);
        paymaster.validatePaymasterUserOp(u, bytes32(0), 0);
    }

    // ------------------------------------------------------------------------------------
    //
    //    PaymasterConfigLengthInvalid — ERC20 config too short
    //
    // ------------------------------------------------------------------------------------

    function test_revert_erc20_config_length_invalid() external {
        PackedUserOperation memory u;
        u.sender = randomEoa;
        // mode=ERC20(1), allowAll=true → byte = (1 << 1) | 1 = 0x03
        u.paymasterAndData = abi.encodePacked(
            address(paymaster),
            uint128(GAS),
            uint128(GAS),
            uint8(0x03), // mode=ERC20, allowAllBundlers=true
            new bytes(10) // too short (needs >= 117)
        );

        vm.expectRevert(Errors.PaymasterConfigLengthInvalid.selector);
        vm.prank(Constants.EP_V9_ADDRESS);
        paymaster.validatePaymasterUserOp(u, bytes32(0), 0);
    }

    // ------------------------------------------------------------------------------------
    //
    //    TokenAddressInvalid — ERC20 mode, token = address(0)
    //
    // ------------------------------------------------------------------------------------

    function test_revert_erc20_token_address_invalid() external {
        PackedUserOperation memory u;
        u.sender = randomEoa;
        u.paymasterAndData = abi.encodePacked(
            address(paymaster),
            uint128(GAS),
            uint128(GAS),
            uint8(0x03), // mode=ERC20, allowAllBundlers=true
            _buildErc20Config(uint8(0), address(0), uint256(1e18), address(0), uint8(2), new bytes(65))
        );

        vm.expectRevert(Errors.TokenAddressInvalid.selector);
        vm.prank(Constants.EP_V9_ADDRESS);
        paymaster.validatePaymasterUserOp(u, bytes32(0), 0);
    }

    // ------------------------------------------------------------------------------------
    //
    //    ExchangeRateInvalid — ERC20 mode, exchangeRate = 0
    //
    // ------------------------------------------------------------------------------------

    function test_revert_erc20_exchange_rate_invalid() external {
        PackedUserOperation memory u;
        u.sender = randomEoa;
        u.paymasterAndData = abi.encodePacked(
            address(paymaster),
            uint128(GAS),
            uint128(GAS),
            uint8(0x03),
            _buildErc20Config(uint8(0), address(sponsorERC20), uint256(0), address(0), uint8(2), new bytes(65))
        );

        vm.expectRevert(Errors.ExchangeRateInvalid.selector);
        vm.prank(Constants.EP_V9_ADDRESS);
        paymaster.validatePaymasterUserOp(u, bytes32(0), 0);
    }

    // ------------------------------------------------------------------------------------
    //
    //    RecipientInvalid — ERC20 mode, recipientPresent but address(0)
    //
    // ------------------------------------------------------------------------------------

    function test_revert_erc20_recipient_invalid() external {
        PackedUserOperation memory u;
        u.sender = randomEoa;
        u.paymasterAndData = abi.encodePacked(
            address(paymaster),
            uint128(GAS),
            uint128(GAS),
            uint8(0x03),
            _buildErc20Config(
                uint8(0x02), // recipientPresent flag (bit 1)
                address(sponsorERC20),
                uint256(1e18),
                address(0), // recipient = address(0) → INVALID
                uint8(2),
                new bytes(65)
            )
        );

        vm.expectRevert(Errors.RecipientInvalid.selector);
        vm.prank(Constants.EP_V9_ADDRESS);
        paymaster.validatePaymasterUserOp(u, bytes32(0), 0);
    }

    // ------------------------------------------------------------------------------------
    //
    //    IncorrectSignerType — ERC20 mode, signerType > 2
    //
    // ------------------------------------------------------------------------------------

    function test_revert_incorrect_signer_type_erc20() external {
        PackedUserOperation memory u;
        u.sender = randomEoa;
        u.paymasterAndData = abi.encodePacked(
            address(paymaster),
            uint128(GAS),
            uint128(GAS),
            uint8(0x03),
            _buildErc20Config(
                uint8(0),
                address(sponsorERC20),
                uint256(1e18),
                address(0),
                uint8(3), // signerType = 3 → INVALID
                new bytes(65)
            )
        );

        vm.expectRevert(Errors.IncorrectSignerType.selector);
        vm.prank(Constants.EP_V9_ADDRESS);
        paymaster.validatePaymasterUserOp(u, bytes32(0), 0);
    }

    // ------------------------------------------------------------------------------------
    //
    //    PaymasterSignatureLengthInvalid — P256 wrong length (verifying)
    //
    // ------------------------------------------------------------------------------------

    function test_revert_signature_length_invalid_p256_verifying() external {
        PackedUserOperation memory u;
        u.sender = randomEoa;
        u.paymasterAndData = abi.encodePacked(
            address(paymaster),
            uint128(GAS),
            uint128(GAS),
            uint8(0x01), // mode=VERIFYING, allowAllBundlers=true
            type(uint48).max,
            uint48(0),
            uint8(0), // signerType = P256
            new bytes(64) // INVALID: P256 requires 128 or 129 bytes
        );

        vm.expectRevert(Errors.PaymasterSignatureLengthInvalid.selector);
        vm.prank(Constants.EP_V9_ADDRESS);
        paymaster.validatePaymasterUserOp(u, bytes32(0), 0);
    }

    // ------------------------------------------------------------------------------------
    //
    //    PaymasterSignatureLengthInvalid — WebAuthn too short (verifying)
    //
    // ------------------------------------------------------------------------------------

    function test_revert_signature_length_invalid_webauthn_verifying() external {
        PackedUserOperation memory u;
        u.sender = randomEoa;
        u.paymasterAndData = abi.encodePacked(
            address(paymaster),
            uint128(GAS),
            uint128(GAS),
            uint8(0x01), // mode=VERIFYING, allowAllBundlers=true
            type(uint48).max,
            uint48(0),
            uint8(1), // signerType = WebAuthnP256
            new bytes(100) // INVALID: WebAuthn requires >= 352 bytes
        );

        vm.expectRevert(Errors.PaymasterSignatureLengthInvalid.selector);
        vm.prank(Constants.EP_V9_ADDRESS);
        paymaster.validatePaymasterUserOp(u, bytes32(0), 0);
    }

    // ------------------------------------------------------------------------------------
    //
    //    PaymasterSignatureLengthInvalid — Secp256k1 wrong length (verifying)
    //
    // ------------------------------------------------------------------------------------

    function test_revert_signature_length_invalid_secp256k1_verifying() external {
        PackedUserOperation memory u;
        u.sender = randomEoa;
        u.paymasterAndData = abi.encodePacked(
            address(paymaster),
            uint128(GAS),
            uint128(GAS),
            uint8(0x01), // mode=VERIFYING, allowAllBundlers=true
            type(uint48).max,
            uint48(0),
            uint8(2), // signerType = Secp256k1
            new bytes(32) // INVALID: Secp256k1 requires 64 or 65 bytes
        );

        vm.expectRevert(Errors.PaymasterSignatureLengthInvalid.selector);
        vm.prank(Constants.EP_V9_ADDRESS);
        paymaster.validatePaymasterUserOp(u, bytes32(0), 0);
    }

    // ------------------------------------------------------------------------------------
    //
    //    PaymasterSignatureLengthInvalid — Secp256k1 wrong length (ERC20)
    //
    // ------------------------------------------------------------------------------------

    function test_revert_signature_length_invalid_secp256k1_erc20() external {
        PackedUserOperation memory u;
        u.sender = randomEoa;
        u.paymasterAndData = abi.encodePacked(
            address(paymaster),
            uint128(GAS),
            uint128(GAS),
            uint8(0x03), // mode=ERC20, allowAllBundlers=true
            _buildErc20Config(
                uint8(0),
                address(sponsorERC20),
                uint256(1e18),
                address(0),
                uint8(2), // signerType = Secp256k1
                new bytes(32) // INVALID: requires 64 or 65 bytes
            )
        );

        vm.expectRevert(Errors.PaymasterSignatureLengthInvalid.selector);
        vm.prank(Constants.EP_V9_ADDRESS);
        paymaster.validatePaymasterUserOp(u, bytes32(0), 0);
    }

    // ------------------------------------------------------------------------------------
    //
    //    PaymasterConfigLengthInvalid — preFund flag set, config truncated
    //
    // ------------------------------------------------------------------------------------

    function test_revert_erc20_config_preFund_length_invalid() external {
        PackedUserOperation memory u;
        u.sender = randomEoa;
        // Build base config (117 bytes) with preFund flag (bit 2) set but no extra 16 bytes
        u.paymasterAndData = abi.encodePacked(
            address(paymaster),
            uint128(GAS),
            uint128(GAS),
            uint8(0x03), // mode=ERC20, allowAllBundlers=true
            _buildErc20ConfigBase(uint8(0x04)) // preFund flag set, no optional bytes appended
        );

        vm.expectRevert(Errors.PaymasterConfigLengthInvalid.selector);
        vm.prank(Constants.EP_V9_ADDRESS);
        paymaster.validatePaymasterUserOp(u, bytes32(0), 0);
    }

    // ------------------------------------------------------------------------------------
    //
    //    PaymasterConfigLengthInvalid — constantFee flag set, config truncated
    //
    // ------------------------------------------------------------------------------------

    function test_revert_erc20_config_constantFee_length_invalid() external {
        PackedUserOperation memory u;
        u.sender = randomEoa;
        // constantFee flag (bit 0) set but no extra 16 bytes
        u.paymasterAndData = abi.encodePacked(
            address(paymaster),
            uint128(GAS),
            uint128(GAS),
            uint8(0x03),
            _buildErc20ConfigBase(uint8(0x01)) // constantFee flag set, no optional bytes
        );

        vm.expectRevert(Errors.PaymasterConfigLengthInvalid.selector);
        vm.prank(Constants.EP_V9_ADDRESS);
        paymaster.validatePaymasterUserOp(u, bytes32(0), 0);
    }

    // ------------------------------------------------------------------------------------
    //
    //    PaymasterConfigLengthInvalid — recipient flag set, config truncated
    //
    // ------------------------------------------------------------------------------------

    function test_revert_erc20_config_recipient_length_invalid() external {
        PackedUserOperation memory u;
        u.sender = randomEoa;
        // recipient flag (bit 1) set but no extra 20 bytes
        u.paymasterAndData = abi.encodePacked(
            address(paymaster),
            uint128(GAS),
            uint128(GAS),
            uint8(0x03),
            _buildErc20ConfigBase(uint8(0x02)) // recipient flag set, no optional bytes
        );

        vm.expectRevert(Errors.PaymasterConfigLengthInvalid.selector);
        vm.prank(Constants.EP_V9_ADDRESS);
        paymaster.validatePaymasterUserOp(u, bytes32(0), 0);
    }

    // ------------------------------------------------------------------------------------
    //
    //                                        Helpers
    //
    // ------------------------------------------------------------------------------------

    function _deployment() internal {
        Key[] memory kS = new Key[](1);
        kS[0] = signer;

        _deploy(superAdmin, admin, kS, IEntryPoint(Constants.EP_V9_ADDRESS), webAuthnVerifier, bundlers);
    }

    /// @dev Build minimal ERC20 config bytes.
    /// Layout: [flags(1)] [validUntil(6)] [validAfter(6)] [token(20)] [postOpGas(16)]
    ///         [exchangeRate(32)] [paymasterValidationGasLimit(16)] [treasury(20)]
    ///         [optional: recipient(20)] [signerType(1)] [signature(variable)]
    function _buildErc20Config(
        uint8 _flags,
        address _token,
        uint256 _exchangeRate,
        address _recipient,
        uint8 _signerType,
        bytes memory _signature
    )
        internal
        view
        returns (bytes memory)
    {
        bytes memory base = abi.encodePacked(
            _flags,
            type(uint48).max, // validUntil
            uint48(0), // validAfter
            _token,
            uint128(GAS), // postOpGas
            _exchangeRate,
            uint128(GAS), // paymasterValidationGasLimit
            __PAYMASTER_SUPER_ADMIN_ADDRESS_EOA // treasury
        );

        if (_flags & 0x02 != 0) {
            base = abi.encodePacked(base, _recipient);
        }

        return abi.encodePacked(base, _signerType, _signature);
    }

    /// @dev Build ERC20 config base (117 bytes) with flags set but NO optional field bytes appended.
    /// Used to test PaymasterConfigLengthInvalid for optional fields.
    function _buildErc20ConfigBase(uint8 _flags) internal view returns (bytes memory) {
        return abi.encodePacked(
            _flags,
            type(uint48).max, // validUntil (6)
            uint48(0), // validAfter (6)
            address(sponsorERC20), // token (20)
            uint128(GAS), // postOpGas (16)
            uint256(1e18), // exchangeRate (32)
            uint128(GAS), // paymasterValidationGasLimit (16)
            __PAYMASTER_SUPER_ADMIN_ADDRESS_EOA // treasury (20)
            // Total: 1+6+6+20+16+32+16+20 = 117 bytes — no signerType, no signature, no optional fields
        );
    }
}
