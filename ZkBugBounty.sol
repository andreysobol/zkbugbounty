// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

contract ZkBugBounty {

    function businessLogic(bytes calldata transition, bytes32 nextState /*, proofData */) public {
        bytes32 transitionHash = sha256(transition);
        
        /* verify_proof(proofData, transitionHash, nextState) */
        return;
    }

    function proofOfHack() public {
        return;
    }

}
