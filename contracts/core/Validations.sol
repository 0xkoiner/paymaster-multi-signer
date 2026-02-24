// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Events } from "../type/Events.sol";
import { Errors } from "../type/Errors.sol";
import { BasePaymaster } from "./BasePaymaster.sol";
import { UserOperationLib } from "@account-abstraction/contracts/core/UserOperationLib.sol";
import { PostOpMode, Types, ERC20PaymasterData, ERC20PostOpContext } from "../type/Types.sol";
import { PackedUserOperation } from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";

using UserOperationLib for PackedUserOperation;

contract Validations is BasePaymaster {
    constructor() { }

    function validatePaymasterUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 requiredPreFund
    )
        external
        override
        returns (bytes memory context, uint256 validationData)
    {
        _requireFromEntryPoint();
        return _validatePaymasterUserOp(userOp, userOpHash, requiredPreFund);
    }

    function postOp(
        PostOpMode mode,
        bytes calldata context,
        uint256 actualGasCost,
        uint256 actualUserOpFeePerGas
    )
        external
        override
    {
        _requireFromEntryPoint();
        _postOp(mode, context, actualGasCost, actualUserOpFeePerGas);
    }

    function _validatePaymasterUserOp(
        PackedUserOperation calldata _userOp,
        bytes32 _userOpHash,
        uint256 _requiredPreFund
    )
        internal
        returns (bytes memory, uint256)
    {
        (uint8 mode, bool allowAllBundlers, bytes calldata paymasterConfig) =
            _parsePaymasterAndData(_userOp.paymasterAndData, Types.PAYMASTER_DATA_OFFSET);

        if (!allowAllBundlers && !isBundlerAllowed[tx.origin]) {
            revert Errors.BundlerNotAllowed(tx.origin);
        }

        if (mode != Types.ERC20_MODE && mode != Types.VERIFYING_MODE) {
            revert Errors.PaymasterModeInvalid();
        }

        bytes memory context;
        uint256 validationData;

        if (mode == Types.VERIFYING_MODE) {
            (context, validationData) = _validateVerifyingMode(_userOp, paymasterConfig, _userOpHash);
        }

        if (mode == Types.ERC20_MODE) {
            (context, validationData) =
                _validateERC20Mode(mode, _userOp, paymasterConfig, _userOpHash, _requiredPreFund);
        }

        return (context, validationData);
    }

    function _validateVerifyingMode(
        PackedUserOperation calldata _userOp,
        bytes calldata _paymasterConfig,
        bytes32 _userOpHash
    )
        internal
        returns (bytes memory, uint256)
    {
        (uint48 validUntil, uint48 validAfter, bytes calldata signature) = _parseVerifyingConfig(_paymasterConfig);

        bytes32 hash = MessageHashUtils.toEthSignedMessageHash(getHash(Types.VERIFYING_MODE, _userOp));
        address recoveredSigner = ECDSA.recover(hash, signature);

        bool isSignatureValid = signers[recoveredSigner];
        uint256 validationData = _packValidationData(!isSignatureValid, validUntil, validAfter);

        emit Events.UserOperationSponsored(_userOpHash, _userOp.getSender(), Types.VERIFYING_MODE, address(0), 0, 0);
        return ("", validationData);
    }

    function _validateERC20Mode(
        uint8 _mode,
        PackedUserOperation calldata _userOp,
        bytes calldata _paymasterConfig,
        bytes32 _userOpHash,
        uint256 _requiredPreFund
    )
        internal
        returns (bytes memory, uint256)
    {
        ERC20PaymasterData memory cfg = _parseErc20Config(_paymasterConfig);

        bytes32 hash = MessageHashUtils.toEthSignedMessageHash(getHash(_mode, _userOp));
        address recoveredSigner = ECDSA.recover(hash, cfg.signature);

        bool isSignatureValid = signers[recoveredSigner];
        uint256 validationData = _packValidationData(!isSignatureValid, cfg.validUntil, cfg.validAfter);
        bytes memory context = _createPostOpContext(_userOp, _userOpHash, cfg, _requiredPreFund);

        if (!isSignatureValid) {
            return (context, validationData);
        }

        uint256 costInToken = getCostInToken(_requiredPreFund, 0, 0, cfg.exchangeRate);

        if (cfg.preFundInToken > costInToken) {
            revert Errors.PreFundTooHigh();
        }

        if (cfg.preFundInToken > 0) {
            SafeTransferLib.safeTransferFrom(cfg.token, _userOp.sender, cfg.treasury, cfg.preFundInToken);
        }

        return (context, validationData);
    }

    function _expectedPenaltyGasCost(
        uint256 _actualGasCost,
        uint256 _actualUserOpFeePerGas,
        uint128 postOpGas,
        uint256 preOpGasApproximation,
        uint256 executionGasLimit
    )
        public
        pure
        virtual
        returns (uint256)
    {
        uint256 executionGasUsed = 0;
        uint256 actualGas = _actualGasCost / _actualUserOpFeePerGas + postOpGas;

        if (actualGas > preOpGasApproximation) {
            executionGasUsed = actualGas - preOpGasApproximation;
        }

        uint256 expectedPenaltyGas = 0;
        if (executionGasLimit > executionGasUsed) {
            expectedPenaltyGas = ((executionGasLimit - executionGasUsed) * Types.PENALTY_PERCENT) / 100;
        }

        return expectedPenaltyGas * _actualUserOpFeePerGas;
    }

    function _postOp(
        PostOpMode, /* mode */
        bytes calldata _context,
        uint256 _actualGasCost,
        uint256 _actualUserOpFeePerGas
    )
        internal
    {
        ERC20PostOpContext memory ctx = _parsePostOpContext(_context);

        uint256 expectedPenaltyGasCost = _expectedPenaltyGasCost(
            _actualGasCost, _actualUserOpFeePerGas, ctx.postOpGas, ctx.preOpGasApproximation, ctx.executionGasLimit
        );

        uint256 actualGasCost = _actualGasCost + expectedPenaltyGasCost;

        uint256 costInToken =
            getCostInToken(actualGasCost, ctx.postOpGas, _actualUserOpFeePerGas, ctx.exchangeRate) + ctx.constantFee;

        uint256 absoluteCostInToken =
            costInToken > ctx.preFundCharged ? costInToken - ctx.preFundCharged : ctx.preFundCharged - costInToken;

        SafeTransferLib.safeTransferFrom(
            ctx.token,
            costInToken > ctx.preFundCharged ? ctx.sender : ctx.treasury,
            costInToken > ctx.preFundCharged ? ctx.treasury : ctx.sender,
            absoluteCostInToken
        );

        uint256 preFundInToken = (ctx.preFund * ctx.exchangeRate) / 1e18;

        if (ctx.recipient != address(0) && preFundInToken > costInToken) {
            SafeTransferLib.safeTransferFrom(ctx.token, ctx.sender, ctx.recipient, preFundInToken - costInToken);
        }

        emit Events.UserOperationSponsored(ctx.userOpHash, ctx.sender, Types.ERC20_MODE, ctx.token, costInToken, ctx.exchangeRate);
    }

    function getHash(uint8 _mode, PackedUserOperation calldata _userOp) public view virtual returns (bytes32) {
        if (_mode == Types.VERIFYING_MODE) {
            return _getHash(_userOp, Types.MODE_AND_ALLOW_ALL_BUNDLERS_LENGTH + Types.VERIFYING_PAYMASTER_DATA_LENGTH);
        } else {
            uint8 paymasterDataLength = Types.MODE_AND_ALLOW_ALL_BUNDLERS_LENGTH + Types.ERC20_PAYMASTER_DATA_LENGTH;

            uint8 combinedByte =
                uint8(_userOp.paymasterAndData[Types.PAYMASTER_DATA_OFFSET + Types.MODE_AND_ALLOW_ALL_BUNDLERS_LENGTH]);
            // constantFeePresent is in the *lowest* bit
            bool constantFeePresent = (combinedByte & 0x01) != 0;
            // recipientPresent is in the second lowest bit
            bool recipientPresent = (combinedByte & 0x02) != 0;
            // preFundPresent is in the third lowest bit
            bool preFundPresent = (combinedByte & 0x04) != 0;

            if (preFundPresent) {
                paymasterDataLength += 16;
            }

            if (constantFeePresent) {
                paymasterDataLength += 16;
            }

            if (recipientPresent) {
                paymasterDataLength += 20;
            }

            return _getHash(_userOp, paymasterDataLength);
        }
    }

    function _getHash(
        PackedUserOperation calldata _userOp,
        uint256 paymasterDataLength
    )
        internal
        view
        returns (bytes32)
    {
        bytes32 userOpHash = keccak256(
            abi.encode(
                _userOp.getSender(),
                _userOp.nonce,
                _userOp.accountGasLimits,
                _userOp.preVerificationGas,
                _userOp.gasFees,
                keccak256(_userOp.initCode),
                keccak256(_userOp.callData),
                keccak256(_userOp.paymasterAndData[:Types.PAYMASTER_DATA_OFFSET + paymasterDataLength])
            )
        );

        return keccak256(abi.encode(userOpHash, block.chainid));
    }
}
