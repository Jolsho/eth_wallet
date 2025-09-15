// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;
struct multi {
    bool verified;
    bytes1 protocol;
    bytes2 peerIdPrefix;
    bytes8 username;
    address proxy;

    bytes16 ip;
    uint8 rating;
    uint32 rateCount;

    bytes32 peerId;
}

abstract contract Sanitizable {
    error MustBeFull();
    modifier fullMulti(multi memory m) {
        require(isFull(m), MustBeFull());
        _;
    }
    function isFull(multi memory m) public pure 
        returns (bool) 
    {
        return (
            m.protocol != 0 && 
            m.ip != 0 && m.username != 0 && 
            m.peerId != 0
        );
    }

    error MustBeEmpty();
    modifier emptyMulti(multi memory m) {
        require(isEmpty(m), MustBeEmpty());
        _;
    }
    function isEmpty(multi memory m) public pure 
        returns (bool) 
    {
        return (
            m.verified == false &&
            m.protocol == 0 && m.username == 0 && 
            m.ip == 0 && m.peerId == 0
        );
    }
}
