// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Constants } from "../data/Constants.sol";
import { Key } from "../../contracts/type/Types.sol";
import { Test } from "../../lib/forge-std/src/Test.sol";
import { KeysManager } from "../../contracts/core/KeysManager.sol";
import { PaymasterEntry } from "../../contracts/core/PaymasterEntry.sol";
import { EntryPoint } from "../../lib/account-abstraction-v9/contracts/core/EntryPoint.sol";
import { IEntryPoint } from "lib/account-abstraction-v9/contracts/interfaces/IEntryPoint.sol";
import { ERC20Mock } from "lib/openzeppelin-contracts-v5.5.0/contracts/mocks/token/ERC20Mock.sol";
import { Simple7702Account } from "../../lib/account-abstraction-v9/contracts/accounts/Simple7702Account.sol";

contract Data is Test {
    // ------------------------------------------------------------------------------------
    //
    //                                       Storage
    //
    // ------------------------------------------------------------------------------------

    // Contracts
    EntryPoint internal entryPoint;
    KeysManager internal keysManager;
    PaymasterEntry internal paymaster;
    Simple7702Account internal simple7702Account;

    // Paymaster Keys
    uint256 internal __PAYMASTER_SUPER_ADMIN_EOA;
    address internal __PAYMASTER_SUPER_ADMIN_ADDRESS_EOA;
    uint256 internal __PAYMASTER_ADMIN_EOA;
    address internal __PAYMASTER__ADMIN_ADDRESS_EOA;
    uint256 internal __PAYMASTER_SIGNER_EOA;
    address internal __PAYMASTER_SIGNER_ADDRESS_EOA;

    // Bundlers
    address[] internal bundlers;

    // Tokens
    ERC20Mock internal sponsorERC20;

    // Account
    uint256 internal __7702_EOA;
    address internal __7702_ADDRESS_EOA;

    function setUp() public virtual {
        _createKeys();
        entryPoint = new EntryPoint();
        entryPoint = EntryPoint(payable(Constants.EP_V9_ADDRESS));
        sponsorERC20 = new ERC20Mock();
        keysManager = new KeysManager();
        simple7702Account = new Simple7702Account(IEntryPoint(Constants.EP_V9_ADDRESS));
    }

    // ------------------------------------------------------------------------------------
    //
    //                                       Internals
    //
    // ------------------------------------------------------------------------------------

    /// -------------------------------------------------------- Deploy Contracts
    function _deploy(
        Key memory _superAdmin,
        Key memory _admin,
        Key[] memory _signers,
        IEntryPoint _entryPoint,
        address[] memory _allowedBundlers
    )
        internal
    {
        paymaster = new PaymasterEntry(_superAdmin, _admin, _signers, _entryPoint, _allowedBundlers);
    }

    /// -------------------------------------------------------- Create Key Pairs
    function _createKeys() internal {
        (__PAYMASTER_SUPER_ADMIN_ADDRESS_EOA, __PAYMASTER_SUPER_ADMIN_EOA) = makeAddrAndKey("PAYMASTER_SUPER_ADMIN_EOA");
        (__PAYMASTER__ADMIN_ADDRESS_EOA, __PAYMASTER_ADMIN_EOA) = makeAddrAndKey("PAYMASTER_ADMIN_EOA");
        (__PAYMASTER_SIGNER_ADDRESS_EOA, __PAYMASTER_SIGNER_EOA) = makeAddrAndKey("PAYMASTER_SIGNER_EOA");
        (__7702_ADDRESS_EOA, __7702_EOA) = makeAddrAndKey("7702_EOA");
    }

    function _createBundlers(bytes32 _seed, uint256 _size) internal {
        for (uint256 i = 0; i < _size;) {
            bundlers.push(makeAddr(string(abi.encode(i, _seed))));
            unchecked {
                ++i;
            }
        }
    }
}
