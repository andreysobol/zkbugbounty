// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

contract ZkBugBounty {

    bool public stop = false;
    address public owner;

    constructor(address _owner) public {
        owner = _owner;   
    }

    function depositForBounty() public payable {}

    function businessLogic(bytes calldata transition, bytes32 nextState /*, proofData */) public {
        if (!stop) {
            bytes32 transitionHash = sha256(transition);
            
            /* verify_proof(proofData, transitionHash, nextState) */
        }
        return;
    }

    function proofOfHack(
            bytes calldata transition,
            bytes32 startedState,
            bytes calldata proofData) public {
        return;
        if (!stop) {
            /*verify_hack_proof(startedState, transition, proofData);*/
            if true {
                uint amount = address(this).balance;
                (bool success, ) = _to.call{value: amount}("");
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
