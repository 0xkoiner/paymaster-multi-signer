// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Constants } from "../data/Constants.sol";
import { Helpers } from "../helpers/Helpers.t.sol";
import { KeyLib } from "../../contracts/library/KeyLib.sol";
import { Key, SignerType } from "../../contracts/type/Types.sol";
import { IEntryPoint } from "lib/account-abstraction-v9/contracts/interfaces/IEntryPoint.sol";

contract TestFuzzKeyValidation is Helpers {
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
    //    Key role mutual exclusivity
    //
    // ------------------------------------------------------------------------------------

    function test_fuzz_key_role_mutual_exclusivity(
        bool _isSuperAdmin,
        bool _isAdmin,
        uint40 _expiry,
        uint8 _keyTypeSeed
    )
        external
        pure
    {
        uint8 keyType = _keyTypeSeed % 3; // 0, 1, or 2

        Key memory k;
        k.isSuperAdmin = _isSuperAdmin;
        k.isAdmin = _isAdmin;
        k.expiry = _expiry;
        k.keyType = SignerType(keyType);
        k.publicKey = abi.encode(uint256(1)); // non-empty

        bool isSA = k._isSuperAdmin();
        bool isAd = k._isAdmin();
        bool isSi = k._isSigner();

        // At most one role can be true
        uint256 roleCount = (isSA ? 1 : 0) + (isAd ? 1 : 0) + (isSi ? 1 : 0);
        assertTrue(roleCount <= 1, "At most one role should be valid");
    }

    // ------------------------------------------------------------------------------------
    //
    //    SuperAdmin requires max expiry
    //
    // ------------------------------------------------------------------------------------

    function test_fuzz_superAdmin_requires_max_expiry(uint40 _expiry) external pure {
        vm.assume(_expiry != type(uint40).max);

        Key memory k;
        k.isSuperAdmin = true;
        k.isAdmin = false;
        k.expiry = _expiry;
        k.keyType = SignerType.Secp256k1;
        k.publicKey = abi.encode(uint256(1));

        assertFalse(k._isSuperAdmin(), "SuperAdmin must have max expiry");
    }

    // ------------------------------------------------------------------------------------
    //
    //    Admin cannot have max expiry
    //
    // ------------------------------------------------------------------------------------

    function test_fuzz_admin_cannot_have_max_expiry() external pure {
        Key memory k;
        k.isSuperAdmin = false;
        k.isAdmin = true;
        k.expiry = type(uint40).max;
        k.keyType = SignerType.Secp256k1;
        k.publicKey = abi.encode(uint256(1));

        assertFalse(k._isAdmin(), "Admin cannot have max expiry");
    }

    // ------------------------------------------------------------------------------------
    //
    //    Empty public key invalidates all roles
    //
    // ------------------------------------------------------------------------------------

    function test_fuzz_empty_publicKey_invalid(bool _isSuperAdmin, bool _isAdmin, uint40 _expiry) external pure {
        Key memory k;
        k.isSuperAdmin = _isSuperAdmin;
        k.isAdmin = _isAdmin;
        k.expiry = _expiry;
        k.keyType = SignerType.Secp256k1;
        k.publicKey = ""; // empty

        assertFalse(k._isSuperAdmin(), "Empty publicKey cannot be superAdmin");
        assertFalse(k._isAdmin(), "Empty publicKey cannot be admin");
        assertFalse(k._isSigner(), "Empty publicKey cannot be signer");
    }

    // ------------------------------------------------------------------------------------
    //
    //    _keyValidation — expired keys are invalid
    //
    // ------------------------------------------------------------------------------------

    function test_fuzz_keyValidation_expired(uint40 _expiry, uint40 _timestamp) external {
        vm.assume(_timestamp > _expiry);
        vm.assume(_timestamp > 0);

        Key memory k;
        k.expiry = _expiry;

        vm.warp(_timestamp);

        assertFalse(k._keyValidation(), "Expired key should be invalid");
    }

    // ------------------------------------------------------------------------------------
    //
    //    _keyValidation — future keys are valid
    //
    // ------------------------------------------------------------------------------------

    function test_fuzz_keyValidation_valid(uint40 _expiry, uint40 _timestamp) external {
        vm.assume(_expiry >= _timestamp);

        Key memory k;
        k.expiry = _expiry;

        vm.warp(_timestamp);

        assertTrue(k._keyValidation(), "Non-expired key should be valid");
    }

    // ------------------------------------------------------------------------------------
    //
    //    _isAllowedSelector — only 4 selectors allowed
    //
    // ------------------------------------------------------------------------------------

    function test_fuzz_isAllowedSelector_rejects_random(bytes4 _sel) external pure {
        vm.assume(_sel != bytes4(0xd0e30db0)); // deposit
        vm.assume(_sel != bytes4(0x0396cb60)); // addStake
        vm.assume(_sel != bytes4(0xbb9fe6bf)); // unlockStake
        vm.assume(_sel != bytes4(0x56864ab1)); // addSigner

        assertFalse(_sel._isAllowedSelector(), "Random selector should not be allowed");
    }

    // ------------------------------------------------------------------------------------
    //
    //    hash — deterministic and collision-resistant for addresses
    //
    // ------------------------------------------------------------------------------------

    function test_fuzz_hash_deterministic(address _a) external pure {
        bytes32 h1 = _a.hash();
        bytes32 h2 = _a.hash();
        assertEq(h1, h2, "Hash should be deterministic");
    }

    function test_fuzz_hash_different_addresses(address _a, address _b) external pure {
        vm.assume(_a != _b);
        assertTrue(_a.hash() != _b.hash(), "Different addresses should produce different hashes");
    }

    // ------------------------------------------------------------------------------------
    //
    //    getKeys — filters expired keys
    //
    // ------------------------------------------------------------------------------------

    function test_fuzz_getKeys_filters_expired(uint40 _expiry) external {
        // Bound: expiry must be > 1 and < existing signer expiry so only the new key expires
        vm.assume(_expiry > 1);
        vm.assume(_expiry < Constants.EXPIRY);

        Key memory shortLived;
        shortLived.expiry = _expiry;
        shortLived.keyType = SignerType.Secp256k1;
        shortLived.isSuperAdmin = false;
        shortLived.isAdmin = false;
        shortLived.publicKey = abi.encode(makeAddr("fuzz-signer"));

        vm.prank(__PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);
        paymaster.addSigner(shortLived);

        // Before expiry: 4 keys
        vm.warp(_expiry);
        (Key[] memory before,) = paymaster.getKeys();
        assertEq(before.length, 4, "Should have 4 keys before expiry");

        // After expiry: 3 keys (shortLived filtered)
        vm.warp(uint256(_expiry) + 1);
        (Key[] memory after_,) = paymaster.getKeys();
        assertEq(after_.length, 3, "Should have 3 keys after expiry");
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
