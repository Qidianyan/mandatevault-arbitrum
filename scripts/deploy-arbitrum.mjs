import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createPublicClient, createWalletClient, http, formatUnits } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { arbitrum, arbitrumSepolia } from "viem/chains";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ARTIFACTS_DIR = path.resolve(__dirname, "..", "artifacts");

const ARBITRUM_ONE_USDC = "0xaf88d065e77c8cC2239327C5EDb3A432268e5831";
const ARBITRUM_ONE_AAVE_V3_POOL = "0x794a61358D6845594F94dc1DB02A252b5b4814aD";

function loadArtifact(name) {
  const filePath = path.join(ARTIFACTS_DIR, `${name}.json`);
  if (!fs.existsSync(filePath)) {
    throw new Error(`Missing artifact ${name}.json. Run 'npm run compile' first.`);
  }
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

async function main() {
  const isSepolia = process.argv.includes("--sepolia");
  const dryRun = process.argv.includes("--dry-run") || !process.env.DEPLOYER_PRIVATE_KEY;
  const chain = isSepolia ? arbitrumSepolia : arbitrum;
  const rpcUrl = process.env.ARBITRUM_RPC_URL || (isSepolia ? "https://sepolia-rollup.arbitrum.io/rpc" : "https://arb1.arbitrum.io/rpc");

  const publicClient = createPublicClient({
    chain,
    transport: http(rpcUrl, {
      fetchOptions: { headers: { "User-Agent": "MandateVault-Deployer/1.0" } },
    }),
  });

  const blockNumber = await publicClient.getBlockNumber();
  const gasPrice = await publicClient.getGasPrice();
  console.log(`[deploy] Connected to ${chain.name} (chainId=${chain.id}) @ block #${blockNumber}, gasPrice=${formatUnits(gasPrice, 9)} gwei`);

  const registryArt = loadArtifact("ERC8004AgentRegistry");
  const verifierArt = loadArtifact("Eip712MandateVerifier");
  const vaultArt = loadArtifact("MandateVault");
  const poolArt = loadArtifact("IAaveV3Pool");

  if (!isSepolia) {
    const reserve = await publicClient.readContract({
      address: ARBITRUM_ONE_AAVE_V3_POOL,
      abi: poolArt.abi,
      functionName: "getReserveData",
      args: [ARBITRUM_ONE_USDC],
    });
    const aprPct = (Number(reserve.currentLiquidityRate) / 1e25).toFixed(4);
    console.log(`[deploy] Verified Arbitrum One Aave V3 USDC Reserve -> aArbUSDCn=${reserve.aTokenAddress}, APR=${aprPct}%`);
  }

  if (dryRun) {
    console.log("[deploy] Preflight mode complete (set DEPLOYER_PRIVATE_KEY in environment to broadcast live transactions).");
    console.log(`  - ERC8004AgentRegistry bytecode: ${registryArt.bytecodeBytes} bytes`);
    console.log(`  - Eip712MandateVerifier bytecode: ${verifierArt.bytecodeBytes} bytes`);
    console.log(`  - MandateVault bytecode:          ${vaultArt.bytecodeBytes} bytes`);
    return;
  }

  const pk = process.env.DEPLOYER_PRIVATE_KEY;
  const account = privateKeyToAccount(pk.startsWith("0x") ? pk : `0x${pk}`);
  const walletClient = createWalletClient({
    account,
    chain,
    transport: http(rpcUrl, {
      fetchOptions: { headers: { "User-Agent": "MandateVault-Deployer/1.0" } },
    }),
  });

  console.log(`[deploy] Broadcasting from deployer ${account.address}...`);

  const regHash = await walletClient.deployContract({
    abi: registryArt.abi,
    bytecode: registryArt.bytecode,
    args: [account.address],
  });
  const regReceipt = await publicClient.waitForTransactionReceipt({ hash: regHash });

  const verHash = await walletClient.deployContract({
    abi: verifierArt.abi,
    bytecode: verifierArt.bytecode,
    args: [],
  });
  const verReceipt = await publicClient.waitForTransactionReceipt({ hash: verHash });

  const globalDailyCap = 5_000_000_000n; // 5,000 USDC default vault-wide 24h rolling ceiling
  const vaultHash = await walletClient.deployContract({
    abi: vaultArt.abi,
    bytecode: vaultArt.bytecode,
    args: [
      account.address,
      ARBITRUM_ONE_USDC,
      ARBITRUM_ONE_AAVE_V3_POOL,
      regReceipt.contractAddress,
      verReceipt.contractAddress,
      globalDailyCap,
    ],
  });
  const vaultReceipt = await publicClient.waitForTransactionReceipt({ hash: vaultHash });

  const authHash = await walletClient.writeContract({
    address: regReceipt.contractAddress,
    abi: registryArt.abi,
    functionName: "setAuthorizedVault",
    args: [vaultReceipt.contractAddress, true],
  });
  await publicClient.waitForTransactionReceipt({ hash: authHash });

  console.log(JSON.stringify({
    chainId: chain.id,
    erc8004Registry: regReceipt.contractAddress,
    eip712MandateVerifier: verReceipt.contractAddress,
    mandateVault: vaultReceipt.contractAddress,
  }, null, 2));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
