// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

contract ZkBugBounty {

    bool public stop = false;
    address public owner;

    constructor(address _owner) public {
        owner = _owner;   
    }

    function depositForBounty() public payable {}

    function verifyStateTransitionProof(
        bytes32 prevState,
        bytes calldata transition,
        bytes32 nextState,
        bytes calldata proofData
    ) private returns (bool) {
        return true;
    }

    function businessLogic(bytes calldata transition, bytes32 nextState /*, proofData */) public {
        if (!stop) {
            bytes32 transitionHash = sha256(transition);
            
            /* verify_proof(proofData, transitionHash, nextState) */
        }
        return;
    }

    function verifyHackProof(
        bytes32 startedState,
        bytes calldata transition,
        bytes calldata proofData
    ) private returns (bool) {
        return true;
    }

    function proofOfHack(
            bytes calldata transition,
            bytes32 startedState,
            bytes calldata proofData,
            address toWithdraw) public {
        return;
        if (!stop) {
            if (verifyHackProof(
                startedState,
                transition,
                proofData
            )) {
                uint amount = address(this).balance;
                (bool success, ) = toWithdraw.call{value: amount}("");
                require(success, "Failed to send Ether");
            }
        }
        return;
    }

    function recover() public {
        if (msg.sender == owner) {
            stop = true;
        }
    }

}
