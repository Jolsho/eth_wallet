// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./utils/Types.sol";
import "./utils/Admin.sol";

abstract contract MultiStore is AdminControls {
    mapping(address => multi) private multis;
    uint public coverCharge;

    error NotCovered();
    error BadRating();
    error NotVerified();

    // ADMIN -----------------------------------------
    function changeCoverCharge(uint newCharge) public onlyAdmin {
        coverCharge = newCharge;
    }

    // MULTIS ----------------------------------------
    function getMulti(address addr) public view 
        onlyRealAddress(addr)
        returns (multi memory) 
    {
        return multis[addr];
    }

    function setMulti(address addr, multi memory m) public 
        onlyAdminOrPersonal(addr)
    {
        multis[addr] = m;
        m.verified = msg.sender == admin;
        m.rating = 0;
        m.rateCount = 0;
    }

    function removeMulti(address addr) public 
        onlyAdminOrPersonal(addr)
    {
        delete multis[addr];
    }


    // VERIFIED ----------------------------------------
    function setVerified(address addr, bool verified) public 
        onlyAdmin()
    {
        multis[addr].verified = verified;
    }

    modifier isVerifiedOrAdmin()  {
        require(multis[msg.sender].verified || msg.sender == admin, NotVerified());
        _;
    }

    // IPs ----------------------------------------
    function setIP(address addr, bytes16 ip) public 
        onlyAdminOrPersonal(addr)
    {
        multis[addr].ip = ip;
    }

    function setProxy(address addr, address proxy) public 
        onlyAdminOrPersonal(addr)
    {
        multis[addr].proxy = proxy;
    }

    // RATINGs ------------------------------------
    function rate(address addr, uint8 rating) public 
        isVerifiedOrAdmin()
        notSelf(addr)
        onlyRealAddress(addr)
    {
        require(0 < rating  && rating <= 250, BadRating());
        multi storage m = multis[addr];
        uint256 expanded = m.rating * m.rateCount;
        uint256 count = m.rateCount + 1;
        m.rating = uint8( (uint256(rating) + expanded) / count );
        m.rateCount = uint32(count);
    }
}
