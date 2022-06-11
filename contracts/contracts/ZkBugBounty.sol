// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "./IStateTransitionVerifier.sol";
import "./IHackVerifier.sol";

contract ZkBugBounty {

    bool public stop = false;
    address public owner;
    IStateTransitionVerifier public stateTransitionVerifier;
    IHackVerifier public hackVerifier;
    bytes32 public currentState;

    constructor(
        address _owner,
        IStateTransitionVerifier _stateTransitionVerifier,
        IHackVerifier _hackVerifier
    ) {
        owner = _owner;
        stateTransitionVerifier = _stateTransitionVerifier;
        hackVerifier = _hackVerifier;
    }

    function depositForBounty() public payable {}

    function verifyStateTransitionProof(
        bytes32 prevState,
        bytes calldata transition,
        bytes32 nextState,
        bytes calldata proofData
    ) private view returns (bool) {
        return stateTransitionVerifier.verify(prevState, transition, nextState, proofData);
    }

    function businessLogic(bytes calldata transition, bytes32 nextState, bytes calldata proofData) public {
        if (!stop) {
            //bytes32 transitionHash = sha256(transition);
            if (verifyStateTransitionProof(
                currentState,
                transition,
                nextState,
                proofData
            )) {
                currentState = nextState;
            }
        }
        return;
    }

    function verifyHackProof(
        bytes32 startedState,
        bytes calldata transition,
        bytes calldata proofData
    ) private view returns (bool) {
        return hackVerifier.verify(
            startedState,
            transition,
            proofData
        );
    }

    function proofOfHack(
            bytes calldata transition,
            bytes32 startedState,
            bytes calldata proofData,
            address toWithdraw) public {
        if (!stop) {
            if (verifyHackProof(
                startedState,
                transition,
                proofData
            )) {
                uint amount = address(this).balance;
                (bool success, ) = toWithdraw.call{value: amount}("");
                require(success, "Failed to send Ether");
                stop = true;
            }
        }
        return;
    }

    function recover() public {
        if (msg.sender == owner) {
            stop = false;
        }
    }

    function upgradeStateTransitionVerifier(IStateTransitionVerifier _stateTransitionVerifier) public {
        if (msg.sender == owner) {
            stateTransitionVerifier = _stateTransitionVerifier;
        }
    }

    function upgradeHashVerifier(IHackVerifier _hackVerifier) public {
        if (msg.sender == owner) {
            hackVerifier = _hackVerifier;
        }
    }
}
