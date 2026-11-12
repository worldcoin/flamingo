// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// Emits the Billing Contract's events; compiled with solc 0.8.28 (cancun) into the JSON fixture.
contract BillingEventEmitter {
    event Registered(uint64 indexed rpId, uint64 indexed periodStart, uint256 indexed billingNullifier);
    event BilledRpUpdated(uint64 indexed rpId, bool billed);

    function registered(uint64 rpId, uint64 periodStart, uint256 billingNullifier) external {
        emit Registered(rpId, periodStart, billingNullifier);
    }

    function billedRpUpdated(uint64 rpId, bool billed) external {
        emit BilledRpUpdated(rpId, billed);
    }
}
