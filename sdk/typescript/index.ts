import crypto from "node:crypto";
import {
  type Address,
  type Hex,
  concatHex,
  encodeAbiParameters,
  encodePacked,
  keccak256,
  parseAbiParameters,
  stringToHex,
  zeroAddress,
  zeroHash,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";

// -----------------------------------------------------------------------------
// Arbitrum One Canonical Constants
// -----------------------------------------------------------------------------
export const ARBITRUM_ONE_CHAIN_ID = 42161;
export const ARBITRUM_SEPOLIA_CHAIN_ID = 421614;
export const ARBITRUM_ONE_RPC = "https://arb1.arbitrum.io/rpc";
export const ARBITRUM_ONE_USDC: Address = "0xaf88d065e77c8cC2239327C5EDb3A432268e5831";
export const ARBITRUM_ONE_AAVE_V3_POOL: Address = "0x794a61358D6845594F94dc1DB02A252b5b4814aD";
export const ARBITRUM_ONE_AARB_USDCN: Address = "0x724dc807b04555b71ed48a6896b6f41593b8c637";

// -----------------------------------------------------------------------------
// EIP-712 AP2 Mandate Schema (Exact Parity with MandateVault.sol)
// -----------------------------------------------------------------------------
export const MANDATE_EIP712_TYPES = {
  Mandate: [
    { name: "mandateId", type: "bytes32" },
    { name: "agent", type: "address" },
    { name: "maxPerTx", type: "uint256" },
    { name: "maxRolling24h", type: "uint256" },
    { name: "validAfter", type: "uint64" },
    { name: "deadline", type: "uint64" },
    { name: "minProviderReputationBps", type: "uint16" },
    { name: "allowedProvidersRoot", type: "bytes32" },
    { name: "escrowThreshold", type: "uint256" },
    { name: "disputeWindowSeconds", type: "uint64" },
    { name: "verifierOverride", type: "address" },
  ],
} as const;

export interface Ap2Mandate {
  mandateId: Hex;
  agent: Address;
  maxPerTx: bigint;
  maxRolling24h: bigint;
  validAfter: bigint;
  deadline: bigint;
  minProviderReputationBps: number;
  allowedProvidersRoot: Hex;
  escrowThreshold: bigint;
  disputeWindowSeconds: bigint;
  verifierOverride: Address;
}

export interface X402Challenge {
  x402Version: 1;
  scheme: "mandatevault-arbitrum-usdc";
  chainId: number;
  vaultCompatible: true;
  paymentNonce: Hex;
  provider: Address;
  amountUsdc: string; // integer micro-USDC string (6 decimals)
  resourceUri: string;
  resourceHash: Hex;
  categoryHash: Hex;
  expectedPayloadHash: Hex;
  forceEscrow?: boolean;
}

export interface X402SettlementProof {
  paymentNonce: Hex;
  mandateId: Hex;
  agent: Address;
  provider: Address;
  amountUsdc: string;
  txHash: Hex;
  escrowId: string;
}

export interface SettlementExecutionResult {
  txHash: Hex;
  escrowId: bigint;
  gasUsed?: bigint;
}

export interface MandateAgentConfig {
  agentAddress: Address;
  vaultAddress: Address;
  mandate: Ap2Mandate;
  mandateSignature: Hex;
  verifierContext?: Hex;
  merkleProofResolver?: (provider: Address, categoryHash: Hex) => Hex[];
  skipClientPreflight?: boolean;
  settleOnChain: (params: {
    mandate: Ap2Mandate;
    mandateSignature: Hex;
    verifierContext: Hex;
    request: {
      paymentNonce: Hex;
      provider: Address;
      amount: bigint;
      resourceHash: Hex;
      expectedPayloadHash: Hex;
      categoryHash: Hex;
      merkleProof: Hex[];
      forceEscrow: boolean;
    };
  }) => Promise<SettlementExecutionResult>;
  onPayloadMismatchDispute?: (params: {
    escrowId: bigint;
    expectedPayloadHash: Hex;
    observedPayloadHash: Hex;
    reason: string;
  }) => Promise<void>;
  fetchImpl?: typeof fetch;
}

// -----------------------------------------------------------------------------
// EIP-712 Mandate Signing & Digest Calculation
// -----------------------------------------------------------------------------
export async function signAp2Mandate(params: {
  ownerPrivateKey: Hex;
  chainId: number;
  vaultAddress: Address;
  mandate: Ap2Mandate;
}): Promise<Hex> {
  const account = privateKeyToAccount(params.ownerPrivateKey);
  return account.signTypedData({
    domain: {
      name: "MandateVault",
      version: "1",
      chainId: params.chainId,
      verifyingContract: params.vaultAddress,
    },
    types: MANDATE_EIP712_TYPES,
    primaryType: "Mandate",
    message: params.mandate,
  });
}

export function computeMandateDigestOffchain(
  chainId: number,
  vaultAddress: Address,
  mandate: Ap2Mandate,
): Hex {
  const domainTypeHash = keccak256(
    stringToHex("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
  );
  const mandateTypeHash = keccak256(
    stringToHex(
      "Mandate(bytes32 mandateId,address agent,uint256 maxPerTx,uint256 maxRolling24h,uint64 validAfter,uint64 deadline,uint16 minProviderReputationBps,bytes32 allowedProvidersRoot,uint256 escrowThreshold,uint64 disputeWindowSeconds,address verifierOverride)",
    ),
  );

  const domainSeparator = keccak256(
    encodeAbiParameters(parseAbiParameters("bytes32, bytes32, bytes32, uint256, address"), [
      domainTypeHash,
      keccak256(stringToHex("MandateVault")),
      keccak256(stringToHex("1")),
      BigInt(chainId),
      vaultAddress,
    ]),
  );

  const structHash = keccak256(
    encodeAbiParameters(
      parseAbiParameters(
        "bytes32, bytes32, address, uint256, uint256, uint64, uint64, uint16, bytes32, uint256, uint64, address",
      ),
      [
        mandateTypeHash,
        mandate.mandateId,
        mandate.agent,
        mandate.maxPerTx,
        mandate.maxRolling24h,
        mandate.validAfter,
        mandate.deadline,
        mandate.minProviderReputationBps,
        mandate.allowedProvidersRoot,
        mandate.escrowThreshold,
        mandate.disputeWindowSeconds,
        mandate.verifierOverride,
      ],
    ),
  );

  return keccak256(encodePacked(["bytes2", "bytes32", "bytes32"], ["0x1901", domainSeparator, structHash]));
}

// -----------------------------------------------------------------------------
// Sorted-Pair Merkle Allowlist Builder (Matches MandateVault._verifyMerkleProof)
// -----------------------------------------------------------------------------
export function hashAllowlistLeaf(provider: Address, categoryHash: Hex): Hex {
  const inner = keccak256(
    encodeAbiParameters(parseAbiParameters("address, bytes32"), [provider, categoryHash]),
  );
  return keccak256(concatHex([inner]));
}

export function buildProviderAllowlistMerkleTree(
  entries: Array<{ provider: Address; categoryHash: Hex }>,
): {
  root: Hex;
  getProof: (provider: Address, categoryHash: Hex) => Hex[];
} {
  if (entries.length === 0) {
    return { root: zeroHash, getProof: () => [] };
  }
  const leaves = entries.map((e) => hashAllowlistLeaf(e.provider, e.categoryHash));
  const layers: Hex[][] = [leaves];

  while (layers[layers.length - 1].length > 1) {
    const cur = layers[layers.length - 1];
    const next: Hex[] = [];
    for (let i = 0; i < cur.length; i += 2) {
      if (i + 1 === cur.length) {
        next.push(cur[i]);
      } else {
        const [a, b] = BigInt(cur[i]) <= BigInt(cur[i + 1]) ? [cur[i], cur[i + 1]] : [cur[i + 1], cur[i]];
        next.push(keccak256(concatHex([a, b])));
      }
    }
    layers.push(next);
  }

  return {
    root: layers[layers.length - 1][0],
    getProof(provider: Address, categoryHash: Hex): Hex[] {
      const target = hashAllowlistLeaf(provider, categoryHash);
      let idx = layers[0].findIndex((x) => x.toLowerCase() === target.toLowerCase());
      if (idx === -1) return [];
      const proof: Hex[] = [];
      for (let level = 0; level < layers.length - 1; level++) {
        const layer = layers[level];
        const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
        if (siblingIdx < layer.length) {
          proof.push(layer[siblingIdx]);
        }
        idx = Math.floor(idx / 2);
      }
      return proof;
    },
  };
}

export function sha256Hex(payload: string | Uint8Array): Hex {
  const digest = crypto.createHash("sha256").update(payload).digest("hex");
  return `0x${digest}`;
}

// -----------------------------------------------------------------------------
// 3-Line AI Agent x402 Client (`createMandateAgent`)
// -----------------------------------------------------------------------------
export function createMandateAgent(config: MandateAgentConfig) {
  const doFetch = config.fetchImpl ?? globalThis.fetch;

  return {
    mandateId: config.mandate.mandateId,
    vaultAddress: config.vaultAddress,

    async fetch(url: string, init?: RequestInit): Promise<{
      response: Response;
      settled: boolean;
      proof?: X402SettlementProof;
      disputeTriggered?: boolean;
    }> {
      const initialResp = await doFetch(url, init);
      if (initialResp.status !== 402) {
        return { response: initialResp, settled: false };
      }

      const headerRaw = initialResp.headers.get("x-payment-required");
      const challenge: X402Challenge = headerRaw
        ? JSON.parse(headerRaw)
        : ((await initialResp.json()) as { challenge: X402Challenge }).challenge;

      const amount = BigInt(challenge.amountUsdc);

      if (!config.skipClientPreflight) {
        if (amount > config.mandate.maxPerTx) {
          throw new Error(
            `[MandateAgent Preflight] Requested x402 amount ${amount} exceeds AP2 Mandate maxPerTx ${config.mandate.maxPerTx}`,
          );
        }
      }

      const merkleProof = config.merkleProofResolver
        ? config.merkleProofResolver(challenge.provider, challenge.categoryHash)
        : [];

      const execution = await config.settleOnChain({
        mandate: config.mandate,
        mandateSignature: config.mandateSignature,
        verifierContext: config.verifierContext ?? "0x",
        request: {
          paymentNonce: challenge.paymentNonce,
          provider: challenge.provider,
          amount,
          resourceHash: challenge.resourceHash,
          expectedPayloadHash: challenge.expectedPayloadHash ?? zeroHash,
          categoryHash: challenge.categoryHash,
          merkleProof,
          forceEscrow: Boolean(challenge.forceEscrow),
        },
      });

      const proof: X402SettlementProof = {
        paymentNonce: challenge.paymentNonce,
        mandateId: config.mandate.mandateId,
        agent: config.agentAddress,
        provider: challenge.provider,
        amountUsdc: amount.toString(),
        txHash: execution.txHash,
        escrowId: execution.escrowId.toString(),
      };

      const retryHeaders = new Headers(init?.headers);
      retryHeaders.set("x-payment-proof", JSON.stringify(proof));

      const unlockedResp = await doFetch(url, {
        ...init,
        headers: retryHeaders,
      });

      let disputeTriggered = false;
      if (
        unlockedResp.ok &&
        challenge.expectedPayloadHash &&
        challenge.expectedPayloadHash !== zeroHash &&
        execution.escrowId > 0n
      ) {
        const clonedText = await unlockedResp.clone().text();
        const observedHash = sha256Hex(clonedText);
        if (observedHash.toLowerCase() !== challenge.expectedPayloadHash.toLowerCase()) {
          disputeTriggered = true;
          if (config.onPayloadMismatchDispute) {
            await config.onPayloadMismatchDispute({
              escrowId: execution.escrowId,
              expectedPayloadHash: challenge.expectedPayloadHash,
              observedPayloadHash: observedHash,
              reason: "SHA256_PAYLOAD_INTEGRITY_MISMATCH",
            });
          }
        }
      }

      return {
        response: unlockedResp,
        settled: true,
        proof,
        disputeTriggered,
      };
    },
  };
}

// -----------------------------------------------------------------------------
// Live Arbitrum One RPC Telemetry Reader (`https://arb1.arbitrum.io/rpc`)
// -----------------------------------------------------------------------------
export interface ArbitrumOneLiveMetrics {
  chainId: number;
  rpcEndpoint: string;
  blockNumber: number;
  blockTimestamp: number;
  gasPriceGwei: string;
  usdcAddress: Address;
  aavePoolAddress: Address;
  aTokenAddress: Address;
  liquidityIndexRay: string;
  currentLiquidityRateRay: string;
  supplyAprPercent: number;
  supplyApyPercent: number;
  aArbUsdcTotalSupplyUsdc: number;
  poolAvailableCashUsdc: number;
  fetchedAtIso: string;
}

export async function fetchArbitrumOneLiveTelemetry(
  rpcUrl: string = ARBITRUM_ONE_RPC,
): Promise<ArbitrumOneLiveMetrics> {
  const paddedUsdc = ARBITRUM_ONE_USDC.slice(2).toLowerCase().padStart(64, "0");
  const paddedAToken = ARBITRUM_ONE_AARB_USDCN.slice(2).toLowerCase().padStart(64, "0");

  const batch = [
    { jsonrpc: "2.0", id: 1, method: "eth_blockNumber", params: [] },
    { jsonrpc: "2.0", id: 2, method: "eth_gasPrice", params: [] },
    {
      jsonrpc: "2.0",
      id: 3,
      method: "eth_call",
      // IAaveV3Pool.getReserveData(address) = 0x35ea6a75
      params: [{ to: ARBITRUM_ONE_AAVE_V3_POOL, data: `0x35ea6a75${paddedUsdc}` }, "latest"],
    },
    {
      jsonrpc: "2.0",
      id: 4,
      method: "eth_call",
      // IERC20.totalSupply() = 0x18160ddd on aArbUSDCn
      params: [{ to: ARBITRUM_ONE_AARB_USDCN, data: "0x18160ddd" }, "latest"],
    },
    {
      jsonrpc: "2.0",
      id: 5,
      method: "eth_call",
      // IERC20.balanceOf(aArbUSDCn) = 0x70a08231 on Native USDC
      params: [{ to: ARBITRUM_ONE_USDC, data: `0x70a08231${paddedAToken}` }, "latest"],
    },
    {
      jsonrpc: "2.0",
      id: 6,
      method: "eth_getBlockByNumber",
      params: ["latest", false],
    },
  ];

  const resp = await fetch(rpcUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "User-Agent": "MandateVault-Arbitrum-SDK/1.0",
    },
    body: JSON.stringify(batch),
  });

  if (!resp.ok) {
    throw new Error(`Arbitrum One RPC returned HTTP ${resp.status}`);
  }

  const results = (await resp.json()) as Array<{ id: number; result: unknown }>;
  const byId = new Map(results.map((r) => [r.id, r.result]));

  const blockNumber = Number(BigInt(byId.get(1) as string));
  const gasPriceWei = BigInt(byId.get(2) as string);
  const reserveHex = (byId.get(3) as string).slice(2);
  const aSupplyRaw = BigInt(byId.get(4) as string);
  const cashRaw = BigInt(byId.get(5) as string);
  const latestBlock = byId.get(6) as { timestamp: string };

  const word = (idx: number) => reserveHex.slice(idx * 64, (idx + 1) * 64);
  const liquidityIndex = BigInt(`0x${word(1)}`);
  const currentLiquidityRate = BigInt(`0x${word(2)}`);
  const aTokenAddr = (`0x${word(8).slice(24)}` as Address) || zeroAddress;

  const aprDecimal = Number(currentLiquidityRate) / 1e27;
  const secondsPerYear = 31_536_000;
  const apyDecimal = Math.pow(1 + aprDecimal / secondsPerYear, secondsPerYear) - 1;

  return {
    chainId: ARBITRUM_ONE_CHAIN_ID,
    rpcEndpoint: rpcUrl,
    blockNumber,
    blockTimestamp: Number(BigInt(latestBlock.timestamp)),
    gasPriceGwei: (Number(gasPriceWei) / 1e9).toFixed(4),
    usdcAddress: ARBITRUM_ONE_USDC,
    aavePoolAddress: ARBITRUM_ONE_AAVE_V3_POOL,
    aTokenAddress: aTokenAddr,
    liquidityIndexRay: liquidityIndex.toString(),
    currentLiquidityRateRay: currentLiquidityRate.toString(),
    supplyAprPercent: Number((aprDecimal * 100).toFixed(4)),
    supplyApyPercent: Number((apyDecimal * 100).toFixed(4)),
    aArbUsdcTotalSupplyUsdc: Number((Number(aSupplyRaw) / 1e6).toFixed(2)),
    poolAvailableCashUsdc: Number((Number(cashRaw) / 1e6).toFixed(2)),
    fetchedAtIso: new Date().toISOString(),
  };
}
