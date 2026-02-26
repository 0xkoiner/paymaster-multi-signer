// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Errors } from "../type/Errors.sol";
import { Types, ERC20PaymasterData, ERC20PostOpContext } from "../type/Types.sol";
import { UserOperationLib } from "@account-abstraction/contracts/core/UserOperationLib.sol";
import { PackedUserOperation } from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";

using UserOperationLib for PackedUserOperation;

library PaymasterLib {
    function _parsePaymasterAndData(
        bytes calldata _paymasterAndData,
        uint256 _paymasterDataOffset
    )
        internal
        pure
        returns (uint8, bool, bytes calldata)
    {
        if (_paymasterAndData.length < _paymasterDataOffset + 1) {
            revert Errors.PaymasterAndDataLengthInvalid();
        }

        uint8 combinedByte = uint8(_paymasterAndData[_paymasterDataOffset]);
        // allowAllBundlers is in the *lowest* bit
        bool allowAllBundlers = (combinedByte & 0x01) != 0;
        // rest of the bits represent the mode
        uint8 mode = uint8((combinedByte >> 1));

        bytes calldata paymasterConfig = _paymasterAndData[_paymasterDataOffset + 1:];

        return (mode, allowAllBundlers, paymasterConfig);
    }

    function _parseVerifyingConfig(bytes calldata _paymasterConfig)
        internal
        pure
        returns (uint48, uint48, bytes calldata)
    {
        if (_paymasterConfig.length < Types.VERIFYING_PAYMASTER_DATA_LENGTH) {
            revert Errors.PaymasterConfigLengthInvalid();
        }

        uint48 validUntil = uint48(bytes6(_paymasterConfig[0:6]));
        uint48 validAfter = uint48(bytes6(_paymasterConfig[6:12]));
        bytes calldata signature = _paymasterConfig[12:];

        if (signature.length != 64 && signature.length != 65) {
            revert Errors.PaymasterSignatureLengthInvalid();
        }

        return (validUntil, validAfter, signature);
    }

    function _parseErc20Config(bytes calldata _paymasterConfig)
        internal
        pure
        returns (ERC20PaymasterData memory config)
    {
        if (_paymasterConfig.length < Types.ERC20_PAYMASTER_DATA_LENGTH) {
            revert Errors.PaymasterConfigLengthInvalid();
        }

        uint128 configPointer = 0;

        uint8 combinedByte = uint8(_paymasterConfig[configPointer]);
        bool constantFeePresent = (combinedByte & 0x01) != 0;
        bool recipientPresent = (combinedByte & 0x02) != 0;
        bool preFundPresent = (combinedByte & 0x04) != 0;

        configPointer += 1;
        config.validUntil = uint48(bytes6(_paymasterConfig[configPointer:configPointer + 6])); // 6 bytes
        configPointer += 6;
        config.validAfter = uint48(bytes6(_paymasterConfig[configPointer:configPointer + 6])); // 6 bytes
        configPointer += 6;
        config.token = address(bytes20(_paymasterConfig[configPointer:configPointer + 20])); // 20 bytes
        configPointer += 20;
        config.postOpGas = uint128(bytes16(_paymasterConfig[configPointer:configPointer + 16])); // 16 bytes
        configPointer += 16;
        config.exchangeRate = uint256(bytes32(_paymasterConfig[configPointer:configPointer + 32])); // 32 bytes
        configPointer += 32;
        config.paymasterValidationGasLimit = uint128(bytes16(_paymasterConfig[configPointer:configPointer + 16])); // 16
        // bytes
        configPointer += 16;
        config.treasury = address(bytes20(_paymasterConfig[configPointer:configPointer + 20])); // 20 bytes
        configPointer += 20;

        config.preFundInToken = uint256(0);
        if (preFundPresent) {
            if (_paymasterConfig.length < configPointer + 16) {
                revert Errors.PaymasterConfigLengthInvalid();
            }

            config.preFundInToken = uint128(bytes16(_paymasterConfig[configPointer:configPointer + 16])); // 16 bytes
            configPointer += 16;
        }
        config.constantFee = uint128(0);
        if (constantFeePresent) {
            if (_paymasterConfig.length < configPointer + 16) {
                revert Errors.PaymasterConfigLengthInvalid();
            }

            config.constantFee = uint128(bytes16(_paymasterConfig[configPointer:configPointer + 16])); // 16 bytes
            configPointer += 16;
        }

        config.recipient = address(0);
        if (recipientPresent) {
            if (_paymasterConfig.length < configPointer + 20) {
                revert Errors.PaymasterConfigLengthInvalid();
            }

            config.recipient = address(bytes20(_paymasterConfig[configPointer:configPointer + 20])); // 20 bytes
            configPointer += 20;
        }
        config.signature = _paymasterConfig[configPointer:];

        if (config.token == address(0)) {
            revert Errors.TokenAddressInvalid();
        }

        if (config.exchangeRate == 0) {
            revert Errors.ExchangeRateInvalid();
        }

        if (recipientPresent && config.recipient == address(0)) {
            revert Errors.RecipientInvalid();
        }

        if (config.signature.length != 64 && config.signature.length != 65) {
            revert Errors.PaymasterSignatureLengthInvalid();
        }

        return config;
    }

    function _createPostOpContext(
        PackedUserOperation calldata _userOp,
        bytes32 _userOpHash,
        ERC20PaymasterData memory _cfg,
        uint256 _requiredPreFund
    )
        internal
        pure
        returns (bytes memory)
    {
        uint256 executionGasLimit = _userOp.unpackCallGasLimit() + _userOp.unpackPostOpGasLimit();

        uint256 preOpGasApproximation =
            _userOp.preVerificationGas + _userOp.unpackVerificationGasLimit() + _cfg.paymasterValidationGasLimit;

        return abi.encode(
            ERC20PostOpContext({
                sender: _userOp.sender,
                token: _cfg.token,
                treasury: _cfg.treasury,
                exchangeRate: _cfg.exchangeRate,
                postOpGas: _cfg.postOpGas,
                userOpHash: _userOpHash,
                maxFeePerGas: uint256(0),
                maxPriorityFeePerGas: uint256(0),
                executionGasLimit: executionGasLimit,
                preFund: _requiredPreFund,
                preFundCharged: _cfg.preFundInToken,
                preOpGasApproximation: preOpGasApproximation,
                constantFee: _cfg.constantFee,
                recipient: _cfg.recipient
            })
        );
    }

    function _parsePostOpContext(bytes calldata _context) internal pure returns (ERC20PostOpContext memory ctx) {
        ctx = abi.decode(_context, (ERC20PostOpContext));
    }

    function _getCostInToken(
        uint256 _actualGasCost,
        uint256 _postOpGas,
        uint256 _actualUserOpFeePerGas,
        uint256 _exchangeRate
    )
        public
        pure
        returns (uint256)
    {
        return ((_actualGasCost + (_postOpGas * _actualUserOpFeePerGas)) * _exchangeRate) / 1e18;
    }

    function _getSender(PackedUserOperation calldata _userOp) internal pure returns (address) {
        address data;
        assembly {
            data := calldataload(_userOp)
        }
        return address(uint160(data));
    }
}
