// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Call } from "../type/Types.sol";
import { Errors } from "../type/Errors.sol";
import { MultiSigner } from "./MultiSigner.sol";
import { IBasePaymaster } from "../interface/IBasePaymaster.sol";
import { Exec } from "@account-abstraction/contracts/utils/Exec.sol";
import { PackedUserOperation } from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";

abstract contract BasePaymaster is MultiSigner, IBasePaymaster {
    /// @inheritdoc IBasePaymaster
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    )
        external
        returns (uint256 validationData)
    {
        _requireFromEntryPoint();
        validationData = _validateSignature(userOp, userOpHash);
        _payPrefund(missingAccountFunds);
    }

    /**
     * Validate the signature is valid for this message.
     * @param userOp          - Validate the userOp.signature field.
     * @param userOpHash      - Convenient field: the hash of the request, to check the signature against.
     *                          (also hashes the entrypoint and chain id)
     * @return validationData - Signature and time-range of this operation.
     *                          <20-byte> aggregatorOrSigFail - 0 for valid signature, 1 to mark signature failure,
     *                                    otherwise, an address of an aggregator contract.
     *                          <6-byte> validUntil - Last timestamp this operation is valid at, or 0 for "indefinitely"
     *                          <6-byte> validAfter - first timestamp this operation is valid
     *                          If the account doesn't use time-range, it is enough to return
     *                          SIG_VALIDATION_FAILED value (1) for signature failure.
     *                          Note that the validation code cannot use block.timestamp (or block.number) directly.
     */
    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    )
        internal
        virtual
        returns (uint256 validationData);

    /**
     * Sends to the entrypoint (msg.sender) the missing funds for this transaction.
     * SubClass MAY override this method for better funds management
     * (e.g. send to the entryPoint more than the minimum required, so that in future transactions
     * it will not be required to send again).
     * @param missingAccountFunds - The minimum value this method should send the entrypoint.
     *                              This value MAY be zero, in case there is enough deposit,
     *                              or the userOp has a paymaster.
     */
    function _payPrefund(uint256 missingAccountFunds) internal virtual {
        if (missingAccountFunds != 0) {
            (bool success,) = payable(msg.sender).call{ value: missingAccountFunds }("");
            (success);
            // Ignore failure (its EntryPoint's job to verify, not account.)
        }
    }

    /// @inheritdoc IBasePaymaster
    function deposit() public payable onlySuperAdminOrAdminKeyOrEp {
        entryPoint.depositTo{ value: msg.value }(address(this));
    }

    /// @inheritdoc IBasePaymaster
    function withdrawTo(address payable _withdrawAddress, uint256 _amount) public onlySuperAdminKeyOrEp {
        entryPoint.withdrawTo(_withdrawAddress, _amount);
    }

    /// @inheritdoc IBasePaymaster
    function addStake(uint32 _unstakeDelaySec) external payable onlySuperAdminOrAdminKeyOrEp {
        entryPoint.addStake{ value: msg.value }(_unstakeDelaySec);
    }

    function getDeposit() public view returns (uint256) {
        return entryPoint.balanceOf(address(this));
    }

    /// @inheritdoc IBasePaymaster
    function unlockStake() external onlySuperAdminOrAdminKeyOrEp {
        entryPoint.unlockStake();
    }

    /// @inheritdoc IBasePaymaster
    function withdrawStake(address payable _withdrawAddress) external onlySuperAdminKeyOrEp {
        entryPoint.withdrawStake(_withdrawAddress);
    }

    /**
     * execute a batch of calls.
     * revert on the first call that fails.
     * If the batch reverts, and it contains more than a single call, then wrap the revert with ExecuteError,
     *  to mark the failing call index.
     */
    /// @inheritdoc IBasePaymaster
    function executeBatch(Call[] calldata calls) external virtual {
        _requireFromEntryPoint();

        uint256 callsLength = calls.length;
        for (uint256 i = 0; i < callsLength; i++) {
            Call calldata call = calls[i];
            bool ok = Exec.call(call.target, call.value, call.data, gasleft());
            if (!ok) {
                if (callsLength == 1) {
                    Exec.revertWithReturnData();
                } else {
                    revert Errors.ExecuteError(i, Exec.getReturnData(0));
                }
            }
        }
    }

    /// @dev Reverts if the caller is not the bound EntryPoint contract.
    function _requireFromEntryPoint() internal view virtual {
        require(msg.sender == address(entryPoint), Errors.SenderNotEntryPoint());
    }
}
