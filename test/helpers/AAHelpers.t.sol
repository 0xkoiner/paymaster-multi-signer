// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Constants } from "../data/Constants.sol";
import { SignerHelpers } from "./SignerHelpers.sol";
import { SignerType } from "../../contracts/type/Types.sol";
import { IValidations } from "../../contracts/interface/IValidations.sol";
import { IBasePaymaster } from "../../contracts/interface/IBasePaymaster.sol";
import { SignatureCheckerLib } from "lib/solady-v0.1.26/src/utils/SignatureCheckerLib.sol";
import { IEntryPoint } from "lib/account-abstraction-v9/contracts/interfaces/IEntryPoint.sol";
import { PackedUserOperation } from "lib/account-abstraction-v9/contracts/interfaces/PackedUserOperation.sol";

contract AAHelpers is SignerHelpers {
    // ------------------------------------------------------------------------------------
    //
    //                                       Enum/Structs
    //
    // ------------------------------------------------------------------------------------

    // Sponsor type of token used to sponsor user operation
    enum Sponsor_Type {
        ETH,
        ERC20
    }
    // Sponsor type of token used to sponsor user operation
    enum Allow_Bundlers {
        SPECIFIC,
        ALL
    }

    // Struct for calls
    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    uint256 internal constant GAS = 1_900_000;

    // ------------------------------------------------------------------------------------
    //
    //                                       Helpers
    //
    // ------------------------------------------------------------------------------------

    // Deposit ETH into the Paymaster
    function _depositPaymaster() internal {
        vm.prank(address(__PAYMASTER_SUPER_ADMIN_ADDRESS_EOA));
        IBasePaymaster(address(paymaster)).deposit{ value: Constants.ETH_0_1 }();
    }

    // Get nonce for _sender from EntryPoint
    function _getNonce(address _sender) internal view returns (uint256) {
        return IEntryPoint(Constants.EP_V9_ADDRESS).getNonce(_sender, 0);
    }

    // Create UserOperation for AA transaction
    function _getUserOp(
        address _sender,
        uint256 _pk,
        bytes memory _callData,
        Sponsor_Type _sponsorType,
        Allow_Bundlers _allowAllBundlers,
        SignerType _signerType
    )
        internal
        returns (PackedUserOperation[] memory, bytes32 userOpHash)
    {
        PackedUserOperation[] memory u = new PackedUserOperation[](1);
        u[0].sender = _sender;
        u[0].nonce = _getNonce(_sender);
        u[0].accountGasLimits = bytes32(uint256(GAS | (GAS << 128)));
        u[0].gasFees = bytes32(uint256(GAS | (GAS << 128)));
        u[0].callData = _callData;

        if (_sponsorType == Sponsor_Type.ETH) {
            u[0].paymasterAndData = abi.encodePacked(
                address(paymaster), uint128(GAS), uint128(GAS), _allowAllBundlers, type(uint48).max, uint48(0)
            );

            bytes32 hash = SignatureCheckerLib.toEthSignedMessageHash(
                IValidations(address(paymaster)).getHash(0, u[0], _signerType)
            );

            if (_signerType == SignerType.P256) {
                (bytes memory signature, P256PubKey memory pK) = _signHashWithP256(hash, prehash);
                _authorizeSigner(pK, _signerType);
                u[0].paymasterAndData =
                    abi.encodePacked(u[0].paymasterAndData, abi.encodePacked(_signerType, signature));
            } else if (_signerType == SignerType.WebAuthnP256) {
                (bytes memory signature, P256PubKey memory pK) = _signHashWithWebAuthn(hash);
                _authorizeSigner(pK, _signerType);
                u[0].paymasterAndData =
                    abi.encodePacked(u[0].paymasterAndData, abi.encodePacked(_signerType, signature));
            } else if (_signerType == SignerType.Secp256k1) {
                (uint8 v, bytes32 r, bytes32 s) = vm.sign(__PAYMASTER_SIGNER_EOA, hash);
                u[0].paymasterAndData = abi.encodePacked(u[0].paymasterAndData, abi.encodePacked(_signerType, r, s, v));
            }

            userOpHash = IEntryPoint(Constants.EP_V9_ADDRESS).getUserOpHash(u[0]);
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(_pk, userOpHash);
            u[0].signature = abi.encodePacked(r, s, v);
        } else if (_sponsorType == Sponsor_Type.ERC20) {
            u[0].paymasterAndData = abi.encodePacked(
                address(paymaster),
                uint128(GAS),
                uint128(GAS),
                uint8(1) | uint8(1 << 1),
                uint8(0),
                type(uint48).max,
                uint48(0),
                address(sponsorERC20),
                uint128(GAS),
                uint256(1e18),
                uint128(GAS),
                __PAYMASTER_SUPER_ADMIN_ADDRESS_EOA
            );

            bytes32 hash = SignatureCheckerLib.toEthSignedMessageHash(
                IValidations(address(paymaster)).getHash(1, u[0], _signerType)
            );

            if (_signerType == SignerType.P256) {
                (bytes memory signature, P256PubKey memory pK) = _signHashWithP256(hash, prehash);
                _authorizeSigner(pK, _signerType);
                u[0].paymasterAndData =
                    abi.encodePacked(u[0].paymasterAndData, abi.encodePacked(_signerType, signature));
            } else if (_signerType == SignerType.WebAuthnP256) {
                (bytes memory signature, P256PubKey memory pK) = _signHashWithWebAuthn(hash);
                _authorizeSigner(pK, _signerType);
                u[0].paymasterAndData =
                    abi.encodePacked(u[0].paymasterAndData, abi.encodePacked(_signerType, signature));
            } else if (_signerType == SignerType.Secp256k1) {
                (uint8 v, bytes32 r, bytes32 s) = vm.sign(__PAYMASTER_SIGNER_EOA, hash);
                u[0].paymasterAndData = abi.encodePacked(u[0].paymasterAndData, abi.encodePacked(_signerType, r, s, v));
            }

            userOpHash = IEntryPoint(Constants.EP_V9_ADDRESS).getUserOpHash(u[0]);
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(_pk, userOpHash);
            u[0].signature = abi.encodePacked(r, s, v);
        }

        return (u, userOpHash);
    }

    // Relay UserOperation to EntryPoint
    function _relayUserOp(PackedUserOperation[] memory _userOps) internal {
        vm.prank(__PAYMASTER_SUPER_ADMIN_ADDRESS_EOA, __PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);
        IEntryPoint(Constants.EP_V9_ADDRESS).handleOps(_userOps, payable(__PAYMASTER_SUPER_ADMIN_ADDRESS_EOA));
    }

    // Attache designatore to EOA
    function _etch7702(address _eoa, address _impl) internal {
        vm.etch(_eoa, abi.encodePacked(bytes3(0xef0100), address(_impl)));
    }

    function _encodeCall(address _target, uint256 _value, bytes memory _data) internal pure returns (Call memory call) {
        call.target = _target;
        call.value = _value;
        call.data = _data;
    }
}
