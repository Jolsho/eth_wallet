// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./utils/Admin.sol";

abstract contract Coin is AdminControls {
    mapping(address => uint) private balances;

    function mint(address reciever, uint amount) public onlyAdmin {
        balances[reciever] += amount;
    }

    function initUserBalance(address addr) public {
        balances[addr] = 0;
    }

    function removeUserBalance(address addr) internal {
        delete balances[addr];
    }

    function getBalance(address addr) public view returns (uint) {
        return balances[addr];
    }

    event Sent(address from, address to, uint amount);

    error InsufficientBalance(uint requested, uint available);

    function send(address receiver, uint amount) public {
        require(amount <= balances[msg.sender], InsufficientBalance(amount, balances[msg.sender]));
        balances[msg.sender] -= amount;
        balances[receiver] += amount;
        emit Sent(msg.sender, receiver, amount);
    }

    function burn(address addr, uint amount) public {
        if (addr != msg.sender) {
            require(msg.sender == admin, Unauthorized());
        }
        require(amount <= balances[addr], InsufficientBalance(amount, balances[addr]));
        balances[addr] -= amount;
    }
}
