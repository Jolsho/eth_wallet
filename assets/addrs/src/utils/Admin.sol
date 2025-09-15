// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

abstract contract AccessGuards {
    error InvalidAddress();

    modifier onlyRealAddress(address addr) {
        if (addr == address(0)) revert InvalidAddress();
        _;
    }
    modifier notSelf(address addr) {
        if (msg.sender == addr) revert InvalidAddress();
        _;
    }
}

abstract contract AdminControls is AccessGuards {
    address public admin;

    error Unauthorized();

    modifier onlyAdmin() {
        if (msg.sender != admin) revert Unauthorized();
        _;
    }
    modifier onlyAdminOrPersonal(address addr) {
        if (msg.sender != admin && msg.sender != addr) revert Unauthorized();
        _;
    }
    function changeAdmin(address newAdmin) public virtual onlyAdmin onlyRealAddress(newAdmin) {
        admin = newAdmin;
    }
}

