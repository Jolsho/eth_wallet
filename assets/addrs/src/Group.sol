// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./Store.sol";
import "./Coin.sol";

contract MaddrGroup is MultiStore, Coin, Sanitizable {
    constructor(uint _coverCharge, address _admin) {
        admin = _admin;
        coverCharge = _coverCharge;
    }
    event NewMulti(address indexed addr, multi m);
    event RemovedMulti(address indexed addr);

    function NewUser(address addr, multi memory user) public payable 
        onlyRealAddress(addr)
        onlyAdminOrPersonal(addr)
    {
        // Ensure cover charge is paid
        require(msg.value >= coverCharge, NotCovered());

        // Initialize the user/balance
        setMulti(addr,user);
        initUserBalance(addr);

        emit NewMulti(addr, user);
    }

    function RemoveUser(address addr) public 
        onlyRealAddress(addr)
        onlyAdminOrPersonal(addr)
    {
        // Remove the user/balance
        removeMulti(addr);
        removeUserBalance(addr);
        emit RemovedMulti(addr);
    }
}
