```
cd circuit/solidity_plonk_verifier/
cargo build --release
./target/release/solidity_plonk_verifier --verification-key PATH_TO_KEY
cat ./hardhat/contracts/VerificationKey.sol | sed 's%import "hardhat/console.sol";% %g' > PATH_TO_SC/VerificationKey.sol
```
