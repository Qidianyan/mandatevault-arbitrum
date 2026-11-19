import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Common, Hardfork, Mainnet, createCustomCommon } from "@ethereumjs/common";
import { EVMError, createEVM } from "@ethereumjs/evm";
import { Account, createAddressFromString } from "@ethereumjs/util";
import {
  bytesToHex,
  decodeErrorResult,
  decodeFunctionResult,
  encodeDeployData,
  encodeFunctionData,
  getAddress,
  hexToBytes,
  keccak256,
  stringToHex,
} from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CODE_ROOT = path.resolve(__dirname, "..");
const ARTIFACTS_DIR = path.join(CODE_ROOT, "artifacts");
const STYLUS_MANIFEST = path.join(CODE_ROOT, "stylus_verifier", "Cargo.toml");
const STYLUS_BIN_DEBUG = path.join(CODE_ROOT, "stylus_verifier", "target", "debug", "stylus_coprocessor_cli");
const CARGO_BIN = process.env.CARGO_BIN || (fs.existsSync(path.join(os.homedir(), ".cargo", "bin", "cargo")) ? path.join(os.homedir(), ".cargo", "bin", "cargo") : "cargo");

export const ARBITRUM_ONE_CHAIN_ID = 42161;
export const STYLUS_COPROCESSOR_ADDRESS = getAddress("0x0000000000000000000000000000000000579105");

export function loadArtifact(contractName) {
  const filePath = path.join(ARTIFACTS_DIR, `${contractName}.json`);
  if (!fs.existsSync(filePath)) {
    throw new Error(`Artifact not found: ${filePath}. Run 'npm run compile' first.`);
  }
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

let stylusBinaryReady = false;
export function ensureStylusCoprocessorBinary() {
  if (!stylusBinaryReady || !fs.existsSync(STYLUS_BIN_DEBUG)) {
    execFileSync(CARGO_BIN, ["build", "--manifest-path", STYLUS_MANIFEST, "--bin", "stylus_coprocessor_cli"], {
      stdio: "pipe",
    });
    stylusBinaryReady = true;
  }
  return STYLUS_BIN_DEBUG;
}

export function signStylusEd25519Mandate(seed32Hex, digest32Hex) {
  const bin = ensureStylusCoprocessorBinary();
  const out = execFileSync(bin, ["sign", seed32Hex, digest32Hex], { encoding: "utf8" }).trim();
  const parsed = JSON.parse(out);
  return {
    pubkey: parsed.pubkey,
    signature: parsed.signature,
    authorizer: getAddress(parsed.authorizer),
    calldata: parsed.calldata,
  };
}

export function invokeStylusCoprocessorCli(calldataHex) {
  const bin = ensureStylusCoprocessorBinary();
  const out = execFileSync(bin, ["call", calldataHex], { encoding: "utf8" }).trim();
  return hexToBytes(out);
}

export class ArbitrumLocalEvm {
  constructor(evm, common, initialTimestamp = 1_763_450_000n, initialBlockNumber = 525_300_000n) {
    this.evm = evm;
    this.common = common;
    this.timestamp = BigInt(initialTimestamp);
    this.blockNumber = BigInt(initialBlockNumber);
    this.txCounter = 0n;
    this.combinedAbis = [
      ...loadArtifact("MandateVault").abi,
      ...loadArtifact("ERC8004AgentRegistry").abi,
      ...loadArtifact("Eip712MandateVerifier").abi,
      ...loadArtifact("ZeroDevMandateValidator").abi,
      ...loadArtifact("ReferenceKernelV3Account").abi,
      ...loadArtifact("ReferenceEntryPointV07").abi,
      ...loadArtifact("ReferenceUSDC6").abi,
      ...loadArtifact("ReferenceAaveV3Pool").abi,
      ...loadArtifact("ReferenceAArbUSDCn").abi,
    ];
    this.addressCache = new Map();
    this.fundedAddresses = new Set();
    this.fnAbiCache = new WeakMap();
    this.errorSelectorMap = new Map();
    for (const item of this.combinedAbis) {
      if (item.type === "error") {
        const sig = `${item.name}(${(item.inputs ?? []).map((i) => i.type).join(",")})`;
        const sel = keccak256(stringToHex(sig)).slice(0, 10).toLowerCase();
        this.errorSelectorMap.set(sel, [item]);
      }
    }
  }

  addr(hexStr) {
    const key = hexStr.toLowerCase();
    let cached = this.addressCache.get(key);
    if (!cached) {
      cached = createAddressFromString(hexStr);
      this.addressCache.set(key, cached);
    }
    return cached;
  }

  singleFnAbi(abi, functionName) {
    let byName = this.fnAbiCache.get(abi);
    if (!byName) {
      byName = new Map();
      for (const item of abi) {
        if (item.type === "function") {
          byName.set(item.name, [item]);
        }
      }
      this.fnAbiCache.set(abi, byName);
    }
    return byName.get(functionName) ?? abi;
  }

  static async create({
    chainId = ARBITRUM_ONE_CHAIN_ID,
    enableStylusPrecompile = true,
    initialTimestamp = 1_763_450_000n,
  } = {}) {
    const common = createCustomCommon({ chainId }, Mainnet, {
      hardfork: Hardfork.Cancun,
    });

    const customPrecompiles = [];
    if (enableStylusPrecompile) {
      ensureStylusCoprocessorBinary();
      customPrecompiles.push({
        address: createAddressFromString(STYLUS_COPROCESSOR_ADDRESS),
        function: (input) => {
          const calldataHex = bytesToHex(input.data);
          try {
            const returnValue = invokeStylusCoprocessorCli(calldataHex);
            return {
              executionGasUsed: 24_800n, // Measured Stylus WASM Ed25519 verification gas profile
              returnValue,
            };
          } catch {
            return {
              executionGasUsed: 24_800n,
              returnValue: new Uint8Array(0),
              exceptionError: new EVMError("revert"),
            };
          }
        },
      });
    }

    const evm = await createEVM({
      common,
      allowUnlimitedContractSize: false,
      customPrecompiles,
    });

    return new ArbitrumLocalEvm(evm, common, initialTimestamp);
  }

  makeBlock() {
    this._zeroCoinbase ??= this.addr("0x0000000000000000000000000000000000000000");
    this._zeroPrevRandao ??= new Uint8Array(32);
    return {
      header: {
        number: this.blockNumber,
        coinbase: this._zeroCoinbase,
        timestamp: this.timestamp,
        difficulty: 0n,
        prevRandao: this._zeroPrevRandao,
        gasLimit: 32_000_000n,
        baseFeePerGas: 20_000_000n, // 0.02 gwei Arbitrum One L2 basefee
        getBlobGasPrice: () => 1n,
      },
    };
  }

  advanceTime(seconds) {
    this.timestamp += BigInt(seconds);
    this.blockNumber += 1n;
  }

  setTimestamp(newTs) {
    this.timestamp = BigInt(newTs);
    this.blockNumber += 1n;
  }

  async fundEth(addressHex, wei = 10n * 10n ** 18n) {
    const key = addressHex.toLowerCase();
    if (this.fundedAddresses.has(key)) return;
    const addr = this.addr(addressHex);
    const existing = (await this.evm.stateManager.getAccount(addr)) ?? new Account();
    existing.balance = wei;
    await this.evm.stateManager.putAccount(addr, existing);
    this.fundedAddresses.add(key);
  }

  async deployContract({ from, artifactName, args = [], gasLimit = 12_000_000n }) {
    const artifact = loadArtifact(artifactName);
    await this.fundEth(from);
    const deployHex = encodeDeployData({
      abi: artifact.abi,
      bytecode: artifact.bytecode,
      args,
    });

    this.blockNumber += 1n;
    const res = await this.evm.runCall({
      caller: createAddressFromString(from),
      origin: createAddressFromString(from),
      data: hexToBytes(deployHex),
      gasLimit,
      block: this.makeBlock(),
    });

    if (res.execResult.exceptionError) {
      const decoded = this.decodeRevert(res.execResult.returnValue);
      throw new Error(
        `Deploy ${artifactName} reverted (${res.execResult.exceptionError.error}): ${decoded.errorName}(${JSON.stringify(decoded.args, bigIntReplacer)})`,
      );
    }

    return {
      address: getAddress(res.createdAddress.toString()),
      abi: artifact.abi,
      gasUsed: res.execResult.executionGasUsed,
    };
  }

  async writeContract({ from, to, abi, functionName, args = [], gasLimit = 5_000_000n }) {
    await this.fundEth(from);
    const fnAbi = this.singleFnAbi(abi, functionName);
    const dataHex = encodeFunctionData({ abi: fnAbi, functionName, args });
    this.txCounter += 1n;
    this.blockNumber += 1n;
    const callerAddr = this.addr(from);

    const res = await this.evm.runCall({
      caller: callerAddr,
      origin: callerAddr,
      to: this.addr(to),
      data: hexToBytes(dataHex),
      gasLimit,
      block: this.makeBlock(),
    });

    if (res.execResult.exceptionError) {
      const decoded = this.decodeRevert(res.execResult.returnValue);
      const err = new Error(`Execution reverted with ${decoded.errorName}`);
      err.errorName = decoded.errorName;
      err.errorArgs = decoded.args;
      err.gasUsed = res.execResult.executionGasUsed;
      throw err;
    }

    let result = undefined;
    if (res.execResult.returnValue.length > 0) {
      result = decodeFunctionResult({
        abi: fnAbi,
        functionName,
        data: bytesToHex(res.execResult.returnValue),
      });
    }

    const syntheticTxHash = `0x${this.blockNumber.toString(16).padStart(32, "0")}${this.txCounter.toString(16).padStart(32, "0")}`;

    return {
      txHash: syntheticTxHash,
      result,
      gasUsed: res.execResult.executionGasUsed,
      logs: res.execResult.logs ?? [],
    };
  }

  async tryWriteContract({ from, to, abi, functionName, args = [], gasLimit = 5_000_000n }) {
    await this.fundEth(from);
    const fnAbi = this.singleFnAbi(abi, functionName);
    const dataHex = encodeFunctionData({ abi: fnAbi, functionName, args });
    this.txCounter += 1n;
    this.blockNumber += 1n;
    const callerAddr = this.addr(from);

    const res = await this.evm.runCall({
      caller: callerAddr,
      origin: callerAddr,
      to: this.addr(to),
      data: hexToBytes(dataHex),
      gasLimit,
      block: this.makeBlock(),
    });

    if (res.execResult.exceptionError) {
      const ret = res.execResult.returnValue;
      let errorName = "EmptyRevert";
      if (ret && ret.length >= 4) {
        const sel = bytesToHex(ret.subarray(0, 4)).toLowerCase();
        const matched = this.errorSelectorMap.get(sel);
        errorName = matched ? matched[0].name : "RawRevert";
      }
      return { ok: false, errorName, gasUsed: res.execResult.executionGasUsed };
    }

    let result = undefined;
    if (res.execResult.returnValue.length > 0) {
      result = decodeFunctionResult({
        abi: fnAbi,
        functionName,
        data: bytesToHex(res.execResult.returnValue),
      });
    }
    return { ok: true, result, gasUsed: res.execResult.executionGasUsed };
  }

  async readContract({ to, abi, functionName, args = [], from = "0x0000000000000000000000000000000000000001" }) {
    const fnAbi = this.singleFnAbi(abi, functionName);
    const dataHex = encodeFunctionData({ abi: fnAbi, functionName, args });
    const callerAddr = this.addr(from);
    const res = await this.evm.runCall({
      caller: callerAddr,
      origin: callerAddr,
      to: this.addr(to),
      data: hexToBytes(dataHex),
      isStatic: true,
      gasLimit: 3_000_000n,
      block: this.makeBlock(),
    });

    if (res.execResult.exceptionError) {
      const decoded = this.decodeRevert(res.execResult.returnValue);
      throw new Error(`Read ${functionName} reverted: ${decoded.errorName}`);
    }

    return decodeFunctionResult({
      abi: fnAbi,
      functionName,
      data: bytesToHex(res.execResult.returnValue),
    });
  }

  decodeRevert(returnBytes) {
    if (!returnBytes || returnBytes.length < 4) {
      return { errorName: "EmptyRevert", args: [] };
    }
    const hex = bytesToHex(returnBytes);
    const sel = hex.slice(0, 10).toLowerCase();
    const matchedAbi = this.errorSelectorMap.get(sel) ?? this.combinedAbis;
    try {
      const decoded = decodeErrorResult({
        abi: matchedAbi,
        data: hex,
      });
      return { errorName: decoded.errorName, args: decoded.args ?? [] };
    } catch {
      return { errorName: "RawRevert", args: [hex] };
    }
  }
}

function bigIntReplacer(_k, v) {
  return typeof v === "bigint" ? v.toString() : v;
}

/**
 * Deploys the complete MandateVault + Aave V3 + ERC-8004 + Dual-Track Verifier stack on ArbitrumLocalEvm.
 */
export async function deployFullProtocolFixture({
  initialPrincipalUsdc = 1_000_000_000n, // 1,000.00 USDC
  globalMaxRolling24h = 500_000_000n,    // 500.00 USDC vault-wide 24h ceiling
  liquidityIndexRay = 1_054_200_000_000_000_000_000_000_000n, // ~1.0542 RAY
  liquidityRateRay = 30_423_000_000_000_000_000_000_000n,     // ~3.0423% APR in RAY
  enableStylusPrecompile = true,
} = {}) {
  const ownerKey = generatePrivateKey();
  const agentKey = generatePrivateKey();
  const attackerKey = generatePrivateKey();
  const arbitratorKey = generatePrivateKey();

  const owner = privateKeyToAccount(ownerKey);
  const agent = privateKeyToAccount(agentKey);
  const attacker = privateKeyToAccount(attackerKey);
  const arbitrator = privateKeyToAccount(arbitratorKey);

  const trustedProvider = getAddress("0x1111111111111111111111111111111111118004");
  const secondaryProvider = getAddress("0x2222222222222222222222222222222222228004");
  const lowRepProvider = getAddress("0x3333333333333333333333333333333333338004");
  const phishingAddress = getAddress("0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF");

  const chain = await ArbitrumLocalEvm.create({
    chainId: ARBITRUM_ONE_CHAIN_ID,
    enableStylusPrecompile,
  });

  const usdc = await chain.deployContract({
    from: owner.address,
    artifactName: "ReferenceUSDC6",
  });

  const aavePool = await chain.deployContract({
    from: owner.address,
    artifactName: "ReferenceAaveV3Pool",
    args: [usdc.address, liquidityIndexRay, liquidityRateRay],
  });

  const aTokenAddress = await chain.readContract({
    to: aavePool.address,
    abi: aavePool.abi,
    functionName: "aToken",
  });
  const aTokenAbi = loadArtifact("ReferenceAArbUSDCn").abi;

  const registry = await chain.deployContract({
    from: owner.address,
    artifactName: "ERC8004AgentRegistry",
    args: [owner.address],
  });

  const verifier = await chain.deployContract({
    from: owner.address,
    artifactName: "Eip712MandateVerifier",
  });

  const vault = await chain.deployContract({
    from: owner.address,
    artifactName: "MandateVault",
    args: [
      owner.address,
      usdc.address,
      aavePool.address,
      registry.address,
      verifier.address,
      globalMaxRolling24h,
    ],
  });

  // Wire Vault into ERC-8004 Registry & configure Arbitrator
  await chain.writeContract({
    from: owner.address,
    to: registry.address,
    abi: registry.abi,
    functionName: "setAuthorizedVault",
    args: [vault.address, true],
  });
  await chain.writeContract({
    from: owner.address,
    to: vault.address,
    abi: vault.abi,
    functionName: "setArbitrator",
    args: [arbitrator.address],
  });

  // Register Service Providers in ERC-8004 Registry
  const capMarketData = keccak256(stringToHex("ap2.capability.market_data"));
  const capCompute = keccak256(stringToHex("ap2.capability.gpu_inference"));

  await chain.writeContract({
    from: owner.address,
    to: registry.address,
    abi: registry.abi,
    functionName: "registerProvider",
    args: [trustedProvider, 9_200, capMarketData, [capMarketData, capCompute], "ipfs://erc8004/provider-prime"],
  });

  await chain.writeContract({
    from: owner.address,
    to: registry.address,
    abi: registry.abi,
    functionName: "registerProvider",
    args: [secondaryProvider, 8_600, capCompute, [capMarketData, capCompute], "ipfs://erc8004/provider-compute"],
  });

  await chain.writeContract({
    from: owner.address,
    to: registry.address,
    abi: registry.abi,
    functionName: "registerProvider",
    args: [lowRepProvider, 4_500, capMarketData, [capMarketData], "ipfs://erc8004/provider-unverified"],
  });

  // Mint initial USDC to owner and seed Aave V3 pool reserve liquidity, then deposit into MandateVault
  await chain.writeContract({
    from: owner.address,
    to: usdc.address,
    abi: usdc.abi,
    functionName: "mint",
    args: [aavePool.address, 10_000_000_000n],
  });

  if (initialPrincipalUsdc > 0n) {
    await chain.writeContract({
      from: owner.address,
      to: usdc.address,
      abi: usdc.abi,
      functionName: "mint",
      args: [owner.address, initialPrincipalUsdc],
    });
    await chain.writeContract({
      from: owner.address,
      to: usdc.address,
      abi: usdc.abi,
      functionName: "approve",
      args: [vault.address, initialPrincipalUsdc],
    });
    await chain.writeContract({
      from: owner.address,
      to: vault.address,
      abi: vault.abi,
      functionName: "deposit",
      args: [initialPrincipalUsdc],
    });
  }

  return {
    chain,
    accounts: {
      ownerKey,
      agentKey,
      attackerKey,
      arbitratorKey,
      owner,
      agent,
      attacker,
      arbitrator,
      trustedProvider,
      secondaryProvider,
      lowRepProvider,
      phishingAddress,
    },
    capabilities: {
      capMarketData,
      capCompute,
    },
    contracts: {
      usdc,
      aavePool,
      aToken: { address: getAddress(aTokenAddress), abi: aTokenAbi },
      registry,
      verifier,
      vault,
    },
  };
}
