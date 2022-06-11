# ZK Bug Bounty

## Motivation

In a last few yers more than million dollars was stolen from the smart contracts (you can list of biggest hacks in rekt news https://rekt.news/leaderboard/). Classical bug bounty (like immunefi.com) can solve this problem -  hacker will have economic incentive to report vulnerability and get reward. But it's not very effective because hacker have risk that project or escrow will say "it's a not real vulnerability". Thats mean that hacker should become black hacker, if he don't want to hope of project honesty.

We propose to write system, where hacker can prove **formally** and **mathematically** that he found a bug.

```
cd circuit/solidity_plonk_verifier/
cargo build --release
./target/release/solidity_plonk_verifier --verification-key PATH_TO_KEY
cat ./hardhat/contracts/VerificationKey.sol | sed 's%import "hardhat/console.sol";% %g' > PATH_TO_SC/VerificationKey.sol
```
