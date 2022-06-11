const { ethers } = require("hardhat");

async function main() {
  const [deployer] = await ethers.getSigners();

  const Hello = await ethers.getContractFactory("Hello");
  const hello = await Hello.deploy();

  const ZkBugBounty = await ethers.getContractFactory("ZkBugBounty");
  const z = await ZkBugBounty.deploy(deployer.address, hello.address, hello.address);

  console.log("ZkBugBounty address:", z.address);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

