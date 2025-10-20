import { ethers } from "hardhat";

async function main() {
  const factory = await ethers.getContractFactory("Groth16Verifier");
  const verifier = await factory.deploy();
  await verifier.waitForDeployment();

  const address = await verifier.getAddress();
  console.log(`Groth16Verifier deployed to: ${address}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
