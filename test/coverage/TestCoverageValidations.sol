// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Constants } from "../data/Constants.sol";
import { Helpers } from "../helpers/Helpers.t.sol";
import { KeyLib } from "../../contracts/library/KeyLib.sol";
import { Key, SignerType } from "../../contracts/type/Types.sol";
import { IValidations } from "../../contracts/interface/IValidations.sol";
import { IEntryPoint } from "lib/account-abstraction-v9/contracts/interfaces/IEntryPoint.sol";
import { PackedUserOperation } from "lib/account-abstraction-v9/contracts/interfaces/PackedUserOperation.sol";

contract TestCoverageValidations is Helpers {
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

        _deal(__PAYMASTER_SUPER_ADMIN_ADDRESS_EOA, Constants.ETH_1);
        _deal(address(paymaster), Constants.ETH_1);

        _depositPaymaster();
    }

    // ------------------------------------------------------------------------------------
    //
    //    getHash ERC20 mode — optional flags (lines 286-295)
    //
    // ------------------------------------------------------------------------------------

    function test_getHash_erc20_with_preFund_flag() external view {
        PackedUserOperation memory u;
        u.sender = address(paymaster);
        u.paymasterAndData = abi.encodePacked(
            _buildPmdBase(uint8(0x04)), // preFundPresent flag
            uint128(1e18), // preFundInToken
            uint8(2),
            new bytes(65)
        );

        bytes32 hash = IValidations(address(paymaster)).getHash(1, u, SignerType.Secp256k1);
        assertTrue(hash != bytes32(0), "Hash should not be zero");
    }

    function test_getHash_erc20_with_constantFee_flag() external view {
        PackedUserOperation memory u;
        u.sender = address(paymaster);
        u.paymasterAndData = abi.encodePacked(
            _buildPmdBase(uint8(0x01)), // constantFeePresent flag
            uint128(1e18), // constantFee
            uint8(2),
            new bytes(65)
        );

        bytes32 hash = IValidations(address(paymaster)).getHash(1, u, SignerType.Secp256k1);
        assertTrue(hash != bytes32(0), "Hash should not be zero");
    }

    function test_getHash_erc20_with_recipient_flag() external view {
        PackedUserOperation memory u;
        u.sender = address(paymaster);
        u.paymasterAndData = abi.encodePacked(
            _buildPmdBase(uint8(0x02)), // recipientPresent flag
            address(0xdead), // recipient
            uint8(2),
            new bytes(65)
        );

        bytes32 hash = IValidations(address(paymaster)).getHash(1, u, SignerType.Secp256k1);
        assertTrue(hash != bytes32(0), "Hash should not be zero");
    }

    function test_getHash_erc20_with_all_flags() external view {
        PackedUserOperation memory u;
        u.sender = address(paymaster);

        bytes memory base = _buildPmdBase(uint8(0x07)); // all 3 flags
        bytes memory optionals = abi.encodePacked(
            uint128(1e18), // preFundInToken
            uint128(1e18), // constantFee
            address(0xdead) // recipient
        );
        u.paymasterAndData = abi.encodePacked(base, optionals, uint8(2), new bytes(65));

        bytes32 hash = IValidations(address(paymaster)).getHash(1, u, SignerType.Secp256k1);
        assertTrue(hash != bytes32(0), "Hash should not be zero");
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

    /// @dev Build paymasterAndData prefix + ERC20 config base (without optional fields)
    function _buildPmdBase(uint8 _flags) internal view returns (bytes memory) {
        return abi.encodePacked(
            address(paymaster),
            uint128(GAS),
            uint128(GAS),
            uint8(0x03), // mode=ERC20, allowAll=true
            _flags,
            type(uint48).max,
            uint48(0),
            address(sponsorERC20),
            uint128(GAS),
            uint256(1e18),
            uint128(GAS),
            __PAYMASTER_SUPER_ADMIN_ADDRESS_EOA
        );
    }
}
