// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Storage } from "./Storage.sol";
import { Events } from "../type/Events.sol";
import { ManagerAccessControl } from "./ManagerAccessControl.sol";

abstract contract MultiSigner is ManagerAccessControl, Storage {
    constructor(address[] memory _initialSigners) {
        for (uint256 i = 0; i < _initialSigners.length; i++) {
            signers[_initialSigners[i]] = true;
        }
    }

    function removeSigner(address _signer) public onlyAdminOrManager {
        signers[_signer] = false;
        emit Events.SignerRemoved(_signer);
    }

    function addSigner(address _signer) public onlyAdminOrManager {
        signers[_signer] = true;
        emit Events.SignerAdded(_signer);
    }
}
