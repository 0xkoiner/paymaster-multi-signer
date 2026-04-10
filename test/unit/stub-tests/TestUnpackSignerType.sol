// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Constants } from "../../data/Constants.sol";
import { Helpers } from "../../helpers/Helpers.t.sol";
import { Key, SignerType } from "../../../contracts/type/Types.sol";
import { IEntryPoint } from "lib/account-abstraction-v9/contracts/interfaces/IEntryPoint.sol";
import { PackedUserOperation } from "lib/account-abstraction-v9/contracts/interfaces/PackedUserOperation.sol";

contract TestUnpackSignerType is Helpers {
    // ------------------------------------------------------------------------------------
    //
    //                                        Storage
    //
    // ------------------------------------------------------------------------------------

    Key internal superAdmin;
    Key internal admin;
    Key internal signer;
    P256PubKey internal pK;

    function setUp() public override {
        super.setUp();

        superAdmin = _createKeySecp256k1(TypeOfKey.SUPER_ADMIN, __PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);
        admin = _createKeySecp256k1(TypeOfKey.ADMIN, __PAYMASTER__ADMIN_ADDRESS_EOA);
        signer = _createKeySecp256k1(TypeOfKey.SIGNER, __PAYMASTER_SIGNER_ADDRESS_EOA);

        _createBundlers(keccak256("bundlers-2"), 2);

        _deployment();
        _ethc();
    }

    // Test SignerType(uint8(userOp.signature[0])) P256
    function test_unpack_signer_type_p256_validateSignature() external {
        (PackedUserOperation[] memory u, bytes32 hash) = _getUserOp(
            __7702_ADDRESS_EOA, __7702_EOA, hex"", Sponsor_Type.ETH, Allow_Bundlers.ALL, SignerType.Secp256k1
        );

        u[0].signature = _packP256Signer();

        vm.prank(Constants.EP_V9_ADDRESS);
        paymaster.validateUserOp(u[0], hash, 0);
    }

    // Test SignerType(uint8(userOp.signature[0])) WebAuthn
    function test_unpack_signer_type_webauthn_validateSignature() external {
        (PackedUserOperation[] memory u, bytes32 hash) = _getUserOp(
            __7702_ADDRESS_EOA, __7702_EOA, hex"", Sponsor_Type.ETH, Allow_Bundlers.ALL, SignerType.Secp256k1
        );

        u[0].signature = _packWebAuthnSigner(hash);

        vm.prank(Constants.EP_V9_ADDRESS);
        paymaster.validateUserOp(u[0], hash, 0);
    }

    // Test SignerType(uint8(userOp.signature[0])) Eoa
    function test_unpack_signer_type_eoa_validateSignature() external {
        (PackedUserOperation[] memory u, bytes32 hash) = _getUserOp(
            __7702_ADDRESS_EOA, __7702_EOA, hex"", Sponsor_Type.ETH, Allow_Bundlers.ALL, SignerType.Secp256k1
        );

        u[0].signature = _packEoaSigner(hash);

        vm.prank(Constants.EP_V9_ADDRESS);
        paymaster.validateUserOp(u[0], hash, 0);
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

    // Pack P256 Signature
    function _packP256Signer() internal returns (bytes memory signature) {
        pK = P256PubKey(keccak256("x"), keccak256("y"));
        _authorizeSigner(pK, SignerType.P256);
        signature = abi.encodePacked(SignerType.P256, keccak256("r"), keccak256("s"), keccak256("x"), keccak256("y"));
    }

    // Pack WebAuthn Signature
    function _packWebAuthnSigner(bytes32 _hash) internal override returns (bytes memory signature) {
        (signature, pK) = _signHashWithWebAuthn(_hash);
        _authorizeSigner(pK, SignerType.WebAuthnP256);
        signature = abi.encodePacked(SignerType.WebAuthnP256, signature);
    }

    // Pack Eoa Signature
    function _packEoaSigner(bytes32 _hash) internal view returns (bytes memory signature) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(__PAYMASTER_SIGNER_EOA, _hash);
        signature = abi.encodePacked(abi.encodePacked(SignerType.Secp256k1, r, s, v));
    }
}
