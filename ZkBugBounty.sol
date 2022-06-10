// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

contract ZkBugBounty {

    bool public stop = false;

    function businessLogic(bytes calldata transition, bytes32 nextState /*, proofData */) public {
        if (!stop) {
            bytes32 transitionHash = sha256(transition);
            
            /* verify_proof(proofData, transitionHash, nextState) */
        }
        return;
    }

    function proofOfHack() public {
        return;
    }

}
