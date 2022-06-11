# ZK Bug Bounty

## Motivation

In a last few yers more than million dollars was stolen from the smart contracts (you can list of biggest hacks in rekt news https://rekt.news/leaderboard/). Classical bug bounty (like immunefi.com) can solve this problem -  hacker will have economic incentive to report vulnerability and get reward. But it's not very effective because hacker have risk that project or escrow will say "it's a not real vulnerability". Thats mean that hacker should become black hacker, if he don't want to hope of project honesty.

We propose to write system, where hacker can prove **formally** and **mathematically** that he found a bug.

## Architecture

### State Transition Proof

All business logic of user function (for example function `transfer`in some pseudoERC20 Token ) will be implemented as ZK circuit. For example if user Alice want to send money to user Bob - Alice will generate zk proof which will change state of full system from `state0` to `state1`. This proof we will call `State Transition Proof`

```
cd circuit/solidity_plonk_verifier/
cargo build --release
./target/release/solidity_plonk_verifier --verification-key PATH_TO_KEY
cat ./hardhat/contracts/VerificationKey.sol | sed 's%import "hardhat/console.sol";% %g' > PATH_TO_SC/VerificationKey.sol
```

### Hack Proof

Imagine that some hacker found vulnerability. He get on of the historical state of the system `stateX` and apply to this some correct state transitions (when for example Alice send money to Bob and Bob send money to Carrel). And prove this state transition using the same circuit which called `State Transition Proof` as is done by regular user Alice. And if result of this manipulation goes to `incorrectState`: for example money supply was increased - he can easelly prove it using zk. Creteria and rules for inc `incorrectState` should be provided by developers of system and should be part of the `Hack Proof`. Also public input `Hack Proof`should be encrypted by contract owner public key. That's mean that only contract owner will understand where he have problem

### Smart contract

We have 2 main smart contract function
- `businessLogic` function for user to work with our pseudoERC20 Token. Inside `businessLogic` we have proof verification `State Transition Proof` which user will use for transfer money
- `proofOfHack` function which give you all bounty eth if you provide correct `Hack Proof`. This function will push red button and stop smart contract untill owner will recover it.

We have few Secondary Functions:
- `depositForBounty`
- `upgradeStateTransitionVerifier`, `upgradeHashVerifier` - upgradability function for providing new version of zk circiuts
- `recover` - restart smart contract after upgrade
