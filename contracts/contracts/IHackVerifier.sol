// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

interface IHackVerifier {

    function verify(
        bytes32 startedState,
        bytes calldata transition,
        bytes calldata proofData
    ) external view returns (bool);

}
