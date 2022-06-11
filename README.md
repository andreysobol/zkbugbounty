# ZK Bug Bounty

## Motivation

In the last few years more than a billion dollars were stolen from smart contracts (you can see a list of the biggest hacks in [Rekt News](https://rekt.news/leaderboard/)). Classic bug bounty (like [Immunefi](https://immunefi.com)) have a solution to this problem - hacker will have economic incentive to report vulnerability (for reward). But it's not very effective because hacker has risk that project or escrow will say "it's a not real vulnerability". That means that hacker will most probably use such vulnerability next time, instead of reporting it.

We propose to write system, where hacker can prove **formally** and **mathematically** that he found a bug.

## Architecture

### State Transition Proof

All business logic of user function (for example function `transfer`in some pseudoERC20 Token ) will be implemented as ZK circuit. For example, if user Alice wants to send money to user Bob - Alice will generate zk proof, which will change state of full system from `state0` to `state1`. This proof we will call `State Transition Proof`

### Hack Proof

Imagine that some hacker has found vulnerability. He gets historical state of the system `stateX` and applies to it some correct state transitions (for example, transfers: Alice sends money to Bob and Bob sends money to Carrel). He then can prove this state transition using the same circuit, which called `State Transition Proof` as is done by regular users Alice and Bob. In case result of this manipulation goes to `incorrectState`: for example money supply was increased - he can easelly prove it using zk. Criteria and rules for `incorrectState` should be provided by developers of system and should be part of the `Hack Proof`. Also public input `Hack Proof` should be encrypted by contract owner's public key. That means that only contract owner will understand where is the problem

### Smart contract

We have 2 main smart contract functions
- `businessLogic` function for user to work with our pseudoERC20 Token. Inside `businessLogic` we have proof verification `State Transition Proof` which user will use for transfering money
- `proofOfHack` function which give you all bounty eth if you provide correct `Hack Proof`. This function will push red button and stop smart contract untill owner will recover it.

We have few Secondary Functions:
- `depositForBounty`
- `upgradeStateTransitionVerifier`, `upgradeHashVerifier` - upgradability function for providing new version of zk circiuts
- `recover` - restart smart contract after upgrade

## Tools and technologies

- [plonk](https://eprint.iacr.org/2019/953.pdf): prove system with universal trusted setup
- [belman_ce](https://github.com/matter-labs/bellman): fork of original belman with plonk
- [franklin-crypto](https://github.com/matter-labs/franklin-crypto): Gadget library for PLONK/Plookup
- [solidity plonk verifier](https://github.com/andreysobol/solidity_plonk_verifier) solidity plonk verifier with lookup tables
- [rescue poseidon](https://github.com/matter-labs/rescue-poseidon): Rescue and Poseidon circuit implementation 

## How to use it

### Build circtuits

install rust and cargo

```
cd circuit
cargo build
```

### Generate VK

pass

### Generate Solidity Plonk Verifier

```
cd circuit/solidity_plonk_verifier/
cargo build --release
./target/release/solidity_plonk_verifier --verification-key PATH_TO_KEY
cat ./hardhat/contracts/VerificationKey.sol | sed 's%import "hardhat/console.sol";% %g' > PATH_TO_SC/VerificationKey.sol
```

### Compile Smart Contracts

### Deploy Smart Contracts

### Run user transaction

### Run proof of hack
