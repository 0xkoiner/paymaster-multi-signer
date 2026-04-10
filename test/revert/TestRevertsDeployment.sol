// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Constants } from "../data/Constants.sol";
import { Helpers } from "../helpers/Helpers.t.sol";
import { Errors } from "../../contracts/type/Errors.sol";
import { KeyLib } from "../../contracts/library/KeyLib.sol";
import { Key, SignerType } from "../../contracts/type/Types.sol";
import { PaymasterEntry } from "../../contracts/core/PaymasterEntry.sol";
import { IWebAuthnVerifier } from "../../contracts/interface/IWebAuthnVerifier.sol";
import { IEntryPoint } from "lib/account-abstraction-v9/contracts/interfaces/IEntryPoint.sol";

contract TestRevertsDeployment is Helpers {
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
    }

    // ------------------------------------------------------------------------------------
    //
    //                       constructor — invalid superAdmin
    //
    // ------------------------------------------------------------------------------------

    function test_revert_deploy_invalid_superAdmin() external {
        Key memory badSuperAdmin = _createKeySecp256k1(TypeOfKey.ADMIN, __PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);

        Key[] memory kS = new Key[](1);
        kS[0] = signer;

        vm.expectRevert();
        new PaymasterEntry(
            badSuperAdmin,
            admin,
            kS,
            IEntryPoint(Constants.EP_V9_ADDRESS),
            IWebAuthnVerifier(address(webAuthnVerifier)),
            bundlers
        );
    }

    // ------------------------------------------------------------------------------------
    //
    //                       constructor — invalid admin
    //
    // ------------------------------------------------------------------------------------

    function test_revert_deploy_invalid_admin() external {
        Key memory badAdmin = _createKeySecp256k1(TypeOfKey.SUPER_ADMIN, __PAYMASTER__ADMIN_ADDRESS_EOA);

        Key[] memory kS = new Key[](1);
        kS[0] = signer;

        vm.expectRevert();
        new PaymasterEntry(
            superAdmin,
            badAdmin,
            kS,
            IEntryPoint(Constants.EP_V9_ADDRESS),
            IWebAuthnVerifier(address(webAuthnVerifier)),
            bundlers
        );
    }

    // ------------------------------------------------------------------------------------
    //
    //                       constructor — invalid signer
    //
    // ------------------------------------------------------------------------------------

    function test_revert_deploy_invalid_signer() external {
        Key memory badSigner = _createKeySecp256k1(TypeOfKey.ADMIN, makeAddr("bad-signer"));

        Key[] memory kS = new Key[](1);
        kS[0] = badSigner;

        vm.expectRevert();
        new PaymasterEntry(
            superAdmin,
            admin,
            kS,
            IEntryPoint(Constants.EP_V9_ADDRESS),
            IWebAuthnVerifier(address(webAuthnVerifier)),
            bundlers
        );
    }

    // ------------------------------------------------------------------------------------
    //
    //                       constructor — zero bundler address
    //
    // ------------------------------------------------------------------------------------

    function test_revert_deploy_zero_bundler() external {
        address[] memory badBundlers = new address[](1);
        badBundlers[0] = address(0);

        Key[] memory kS = new Key[](1);
        kS[0] = signer;

        vm.expectRevert();
        new PaymasterEntry(
            superAdmin,
            admin,
            kS,
            IEntryPoint(Constants.EP_V9_ADDRESS),
            IWebAuthnVerifier(address(webAuthnVerifier)),
            badBundlers
        );
    }

    // ------------------------------------------------------------------------------------
    //
    //                       constructor — zero entryPoint
    //
    // ------------------------------------------------------------------------------------

    function test_revert_deploy_zero_entryPoint() external {
        Key[] memory kS = new Key[](1);
        kS[0] = signer;

        vm.expectRevert(Errors.AddressZero.selector);
        new PaymasterEntry(
            superAdmin, admin, kS, IEntryPoint(address(0)), IWebAuthnVerifier(address(webAuthnVerifier)), bundlers
        );
    }

    // ------------------------------------------------------------------------------------
    //
    //                       constructor — zero webAuthnVerifier
    //
    // ------------------------------------------------------------------------------------

    function test_revert_deploy_zero_webAuthnVerifier() external {
        Key[] memory kS = new Key[](1);
        kS[0] = signer;

        vm.expectRevert(Errors.AddressZero.selector);
        new PaymasterEntry(
            superAdmin, admin, kS, IEntryPoint(Constants.EP_V9_ADDRESS), IWebAuthnVerifier(address(0)), bundlers
        );
    }
}
