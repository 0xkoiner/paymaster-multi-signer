// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Key } from "../type/Types.sol";
import { Errors } from "../type/Errors.sol";
import { Events } from "../type/Events.sol";
import { KeyLib } from "../library/KeyLib.sol";
import { KeysManager } from "./KeysManager.sol";
import { IMultiSigner } from "../interface/IMultiSigner.sol";
import { EnumerableSetLib } from "@solady/src/utils/EnumerableSetLib.sol";

abstract contract MultiSigner is KeysManager, IMultiSigner {
    using KeyLib for *;
    using EnumerableSetLib for *;

    /// @inheritdoc IMultiSigner
    function addSigner(Key calldata _signer) public onlySuperAdminOrAdminKeyOrEp {
        if (keyHashes.contains(_signer.hash())) revert Errors.KeyAuthorized();
        if (_signer.isSuperAdmin || _signer.isAdmin) revert Errors.IncorrectSignerRole();

        _addKey(_signer);
    }

    /// @inheritdoc IMultiSigner
    function removeSigner(bytes32 _signer) public onlySuperAdminKeyOrEp {
        if (keyStorage[_signer]._isSuperAdmin() || keyStorage[_signer]._isAdmin()) revert Errors.KillSwitch();
        revoke(_signer);
    }
}
