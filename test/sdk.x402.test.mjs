import assert from "node:assert/strict";
import test from "node:test";
import { keccak256, stringToHex, zeroAddress } from "viem";
import { startX402GatewayServer } from "../sdk/typescript/gateway.ts";
import {
  ARBITRUM_ONE_AAVE_V3_POOL,
  ARBITRUM_ONE_CHAIN_ID,
  ARBITRUM_ONE_USDC,
  buildProviderAllowlistMerkleTree,
  createMandateAgent,
  fetchArbitrumOneLiveTelemetry,
  signAp2Mandate,
} from "../sdk/typescript/index.ts";
import { deployFullProtocolFixture } from "./evm_harness.mjs";

test("1. End-to-End TypeScript Agent SDK + Live HTTP 402 Gateway + Corrupted Payload Dispute Freeze", async () => {
  const fixture = await deployFullProtocolFixture({
    initialPrincipalUsdc: 500_000_000n, // 500 USDC
  });
  const { chain, accounts, capabilities, contracts } = fixture;

  const allowlist = buildProviderAllowlistMerkleTree([
    { provider: accounts.trustedProvider, categoryHash: capabilities.capMarketData },
    { provider: accounts.trustedProvider, categoryHash: capabilities.capCompute },
  ]);

  const mandate = {
    mandateId: keccak256(stringToHex("sdk-x402-mandate-001")),
    agent: accounts.agent.address,
    maxPerTx: 10_000_000n,
    maxRolling24h: 50_000_000n,
    validAfter: 1_760_000_000n,
    deadline: 1_950_000_000n,
    minProviderReputationBps: 8_000,
    allowedProvidersRoot: allowlist.root,
    escrowThreshold: 5_000_000n,
    disputeWindowSeconds: 1_800n,
    verifierOverride: zeroAddress,
  };

  const mandateSignature = await signAp2Mandate({
    ownerPrivateKey: accounts.ownerKey,
    chainId: ARBITRUM_ONE_CHAIN_ID,
    vaultAddress: contracts.vault.address,
    mandate,
  });

  const gateway = await startX402GatewayServer({
    port: 0,
    context: {
      vaultAddress: contracts.vault.address,
      providerAddress: accounts.trustedProvider,
      capMarketData: capabilities.capMarketData,
      capCompute: capabilities.capCompute,
      verifyNonceUsedOnChain: async (paymentNonce) => {
        return Boolean(
          await chain.readContract({
            to: contracts.vault.address,
            abi: contracts.vault.abi,
            functionName: "usedPaymentNonces",
            args: [paymentNonce],
          }),
        );
      },
    },
  });

  try {
    let raisedEscrowId = 0n;

    const agentClient = createMandateAgent({
      agentAddress: accounts.agent.address,
      vaultAddress: contracts.vault.address,
      mandate,
      mandateSignature,
      merkleProofResolver: (provider, categoryHash) => allowlist.getProof(provider, categoryHash),
      settleOnChain: async ({ mandate: m, mandateSignature: sig, verifierContext, request }) => {
        const tx = await chain.writeContract({
          from: accounts.agent.address,
          to: contracts.vault.address,
          abi: contracts.vault.abi,
          functionName: "settleX402Payment",
          args: [m, sig, verifierContext, request],
        });
        return {
          txHash: tx.txHash,
          escrowId: tx.result,
          gasUsed: tx.gasUsed,
        };
      },
      onPayloadMismatchDispute: async ({ escrowId, observedPayloadHash, reason }) => {
        raisedEscrowId = escrowId;
        await chain.writeContract({
          from: accounts.agent.address,
          to: contracts.vault.address,
          abi: contracts.vault.abi,
          functionName: "raiseDispute",
          args: [escrowId, observedPayloadHash, reason],
        });
      },
    });

    // A. Normal HTTP 402 -> Atomic On-Chain Settlement -> 200 OK Unlocked Resource
    const feedRes = await agentClient.fetch(`${gateway.baseUrl}/api/x402/market-feed`);
    assert.equal(feedRes.settled, true);
    assert.equal(feedRes.disputeTriggered, false);
    assert.equal(feedRes.response.status, 200);
    const feedJson = await feedRes.response.json();
    assert.equal(feedJson.settledVia, "MandateVault-x402-Atomic");

    // B. Corrupted Dataset Delivery -> SHA-256 Mismatch -> Automatic On-Chain Dispute Freeze & Refund
    const corruptRes = await agentClient.fetch(`${gateway.baseUrl}/api/x402/audit-dataset?corrupt=1`);
    assert.equal(corruptRes.settled, true);
    assert.equal(corruptRes.disputeTriggered, true);
    assert.equal(raisedEscrowId, 1n);

    // Arbitrator refunds the frozen 6.00 USDC directly back into Aave V3
    await chain.writeContract({
      from: accounts.arbitrator.address,
      to: contracts.vault.address,
      abi: contracts.vault.abi,
      functionName: "resolveDispute",
      args: [raisedEscrowId, true],
    });

    const finalPrincipal = await chain.readContract({
      to: contracts.vault.address,
      abi: contracts.vault.abi,
      functionName: "principalDeposited",
    });
    assert.equal(finalPrincipal, 499_750_000n, "Only the 0.25 USDC clean call was spent; 6.00 USDC refunded to Aave V3");
  } finally {
    await gateway.close();
  }
});

test("2. Live Arbitrum One RPC (`https://arb1.arbitrum.io/rpc`) Telemetry Verification", async () => {
  const telemetry = await fetchArbitrumOneLiveTelemetry("https://arb1.arbitrum.io/rpc");
  assert.equal(telemetry.chainId, 42161);
  assert.ok(telemetry.blockNumber > 400_000_000, `Expected Arbitrum One live block > 400M, got ${telemetry.blockNumber}`);
  assert.equal(telemetry.usdcAddress.toLowerCase(), ARBITRUM_ONE_USDC.toLowerCase());
  assert.equal(telemetry.aavePoolAddress.toLowerCase(), ARBITRUM_ONE_AAVE_V3_POOL.toLowerCase());
  assert.equal(telemetry.aTokenAddress.toLowerCase(), "0x724dc807b04555b71ed48a6896b6f41593b8c637");
  assert.ok(telemetry.supplyAprPercent > 0 && telemetry.supplyAprPercent < 50, `Live APR=${telemetry.supplyAprPercent}%`);
  assert.ok(telemetry.aArbUsdcTotalSupplyUsdc > 1_000_000, `Live aArbUSDCn TVL=$${telemetry.aArbUsdcTotalSupplyUsdc}`);
  console.log(
    `[arb1-live] Block #${telemetry.blockNumber} | Gas=${telemetry.gasPriceGwei} gwei | aArbUSDCn APR=${telemetry.supplyAprPercent}% (APY=${telemetry.supplyApyPercent}%) | TVL=$${telemetry.aArbUsdcTotalSupplyUsdc.toLocaleString()}`,
  );
});
