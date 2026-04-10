// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Constants } from "../data/Constants.sol";
import { Helpers } from "../helpers/Helpers.t.sol";
import { Errors } from "../../contracts/type/Errors.sol";
import { KeyLib } from "../../contracts/library/KeyLib.sol";
import { Key, SignerType } from "../../contracts/type/Types.sol";
import { IEntryPoint } from "lib/account-abstraction-v9/contracts/interfaces/IEntryPoint.sol";

contract TestFuzzAccessControl is Helpers {
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
    }

    // ------------------------------------------------------------------------------------
    //
    //    Random address cannot call onlySuperAdminKeyOrEp functions
    //
    // ------------------------------------------------------------------------------------

    function test_fuzz_random_eoa_cannot_authorizeAdmin(address _caller) external {
        vm.assume(_caller != __PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);
        vm.assume(_caller != Constants.EP_V9_ADDRESS);
        vm.assume(_caller != address(paymaster));

        Key memory random = _createKeySecp256k1(TypeOfKey.ADMIN, makeAddr("fuzz-admin"));

        vm.expectRevert(abi.encodeWithSelector(Errors.AccessControlUnauthorizedAccount.selector, _caller));
        vm.prank(_caller);
        paymaster.authorizeAdmin(random);
    }

    // ------------------------------------------------------------------------------------
    //
    //    Random address cannot call onlySuperAdminOrAdminKeyOrEp functions
    //
    // ------------------------------------------------------------------------------------

    function test_fuzz_random_eoa_cannot_deposit(address _caller) external {
        vm.assume(_caller != __PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);
        vm.assume(_caller != __PAYMASTER__ADMIN_ADDRESS_EOA);
        vm.assume(_caller != Constants.EP_V9_ADDRESS);
        vm.assume(_caller != address(paymaster));

        vm.expectRevert(abi.encodeWithSelector(Errors.AccessControlUnauthorizedAccount.selector, _caller));
        vm.prank(_caller);
        paymaster.deposit();
    }

    // ------------------------------------------------------------------------------------
    //
    //    SuperAdmin can always call protected functions
    //
    // ------------------------------------------------------------------------------------

    function test_fuzz_superAdmin_can_add_signer(address _signerEoa) external {
        vm.assume(_signerEoa != address(0));
        vm.assume(_signerEoa != __PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);
        vm.assume(_signerEoa != __PAYMASTER__ADMIN_ADDRESS_EOA);
        vm.assume(_signerEoa != __PAYMASTER_SIGNER_ADDRESS_EOA);

        Key memory newSigner;
        newSigner.expiry = Constants.EXPIRY;
        newSigner.keyType = SignerType.Secp256k1;
        newSigner.isSuperAdmin = false;
        newSigner.isAdmin = false;
        newSigner.publicKey = abi.encode(_signerEoa);

        vm.prank(__PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);
        paymaster.addSigner(newSigner);

        uint256 count = paymaster.keyCount();
        assertEq(count, 4, "Should have 4 keys after adding signer");
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
}
