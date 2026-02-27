// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Key } from "../type/Types.sol";
import { Errors } from "../type/Errors.sol";
import { Events } from "../type/Events.sol";
import { KeyLib } from "../library/KeyLib.sol";
import { KeysManager } from "./KeysManager.sol";
import { EnumerableSetLib } from "@solady/src/utils/EnumerableSetLib.sol";

abstract contract MultiSigner is KeysManager {
    using KeyLib for *;
    using EnumerableSetLib for *;

    function addSigner(address _signer) public onlyAdminOrManager {
        signers[_signer] = true;
        emit Events.SignerAdded(_signer);
    }

    function removeSigner(address _signer) public onlyAdminOrManager {
        signers[_signer] = false;
        emit Events.SignerRemoved(_signer);
    }

    function addSigner(Key calldata _signer) public onlySuperAdminOrAdminKey {
        if (keyHashes.contains(_signer.hash())) revert Errors.KeyAuthorized();
        if (_signer.isSuperAdmin || _signer.isAdmin) revert Errors.IncorrectSignerRole();

        authorize(_signer);
    }

    function removeSigner(bytes32 _signer) public onlySuperAdminKey {
        if (keyStorage[_signer]._isSuperAdmin() || keyStorage[_signer]._isAdmin()) revert Errors.KillSwitch();
        revoke(_signer);
    }
}
