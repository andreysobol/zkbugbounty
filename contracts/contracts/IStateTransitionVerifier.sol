// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

interface IStateTransitionVerifier {

    function verify(
        bytes32 prevState,
        bytes calldata transition,
        bytes32 nextState,
        bytes calldata proofData
    ) external view returns (bool);

}
