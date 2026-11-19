import assert from "node:assert/strict";
import test from "node:test";
import { concatHex, keccak256, padHex, stringToHex, toHex, zeroAddress, zeroHash } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  ARBITRUM_ONE_CHAIN_ID,
  buildProviderAllowlistMerkleTree,
  computeMandateDigestOffchain,
  sha256Hex,
  signAp2Mandate,
} from "../sdk/typescript/index.ts";
import {
  STYLUS_COPROCESSOR_ADDRESS,
  deployFullProtocolFixture,
  signStylusEd25519Mandate,
} from "./evm_harness.mjs";

async function createStandardSignedMandate(fixture, overrides = {}) {
  const { accounts, capabilities, contracts } = fixture;
  const allowlist = buildProviderAllowlistMerkleTree([
    { provider: accounts.trustedProvider, categoryHash: capabilities.capMarketData },
    { provider: accounts.trustedProvider, categoryHash: capabilities.capCompute },
    { provider: accounts.secondaryProvider, categoryHash: capabilities.capCompute },
  ]);

  const mandate = {
    mandateId: keccak256(stringToHex("ap2-mandate-arb1-alpha")),
    agent: accounts.agent.address,
    maxPerTx: 10_000_000n, // 10.00 USDC
    maxRolling24h: 50_000_000n, // 50.00 USDC
    validAfter: 1_760_000_000n,
    deadline: 1_900_000_000n,
    minProviderReputationBps: 8_000,
    allowedProvidersRoot: allowlist.root,
    escrowThreshold: 5_000_000n, // 5.00 USDC
    disputeWindowSeconds: 1_800n, // 30 minutes
    verifierOverride: zeroAddress,
    ...overrides,
  };

  const signature = await signAp2Mandate({
    ownerPrivateKey: accounts.ownerKey,
    chainId: ARBITRUM_ONE_CHAIN_ID,
    vaultAddress: contracts.vault.address,
    mandate,
  });

  return { mandate, signature, allowlist };
}

test("1. Zero-Idle Aave V3 Yield Accrual + Atomic x402 Principal Redemption + Owner Yield Ring-Fencing", async () => {
  const fixture = await deployFullProtocolFixture({
    initialPrincipalUsdc: 1_000_000_000n, // 1,000 USDC
  });
  const { chain, accounts, capabilities, contracts } = fixture;
  const { mandate, signature, allowlist } = await createStandardSignedMandate(fixture);

  // Off-chain EIP-712 digest MUST match Solidity computeMandateDigest byte-for-byte
  const onChainDigest = await chain.readContract({
    to: contracts.vault.address,
    abi: contracts.vault.abi,
    functionName: "computeMandateDigest",
    args: [mandate],
  });
  const offChainDigest = computeMandateDigestOffchain(
    ARBITRUM_ONE_CHAIN_ID,
    contracts.vault.address,
    mandate,
  );
  assert.equal(onChainDigest.toLowerCase(), offChainDigest.toLowerCase());

  // Advance 30 days so Aave V3 accrues real interest on 1,000 USDC (~2.50 USDC @ 3.0423% APR)
  chain.advanceTime(30 * 86_400);

  const metricsBefore = await chain.readContract({
    to: contracts.vault.address,
    abi: contracts.vault.abi,
    functionName: "vaultYieldMetrics",
  });
  assert.equal(metricsBefore[1], 1_000_000_000n, "Active principal is 1,000 USDC");
  assert.ok(metricsBefore[2] >= 2_400_000n, `Expected >=2.40 USDC yield, got ${metricsBefore[2]}`);

  // Settle a 0.25 USDC HTTP 402 micropayment atomically from Aave V3
  const merkleProof = allowlist.getProof(accounts.trustedProvider, capabilities.capMarketData);
  const settleTx = await chain.writeContract({
    from: accounts.agent.address,
    to: contracts.vault.address,
    abi: contracts.vault.abi,
    functionName: "settleX402Payment",
    args: [
      mandate,
      signature,
      "0x",
      {
        paymentNonce: keccak256(stringToHex("nonce-001")),
        provider: accounts.trustedProvider,
        amount: 250_000n,
        resourceHash: keccak256(stringToHex("/v1/market-feed")),
        expectedPayloadHash: zeroHash,
        categoryHash: capabilities.capMarketData,
        merkleProof,
        forceEscrow: false,
      },
    ],
  });

  assert.equal(settleTx.result, 0n, "Micro-settlement bypasses escrow directly");
  assert.ok(settleTx.gasUsed < 300_000n, `Atomic x402 settlement gas=${settleTx.gasUsed}`);

  const providerUsdc = await chain.readContract({
    to: contracts.usdc.address,
    abi: contracts.usdc.abi,
    functionName: "balanceOf",
    args: [accounts.trustedProvider],
  });
  assert.equal(providerUsdc, 250_000n);

  // Verify ERC-8004 reputation increased by +25 bps (from 9200 to 9225)
  const providerIdentity = await chain.readContract({
    to: contracts.registry.address,
    abi: contracts.registry.abi,
    functionName: "getAgentIdentity",
    args: [accounts.trustedProvider],
  });
  assert.equal(Number(providerIdentity.reputationBps), 9_225);
  assert.equal(providerIdentity.fulfilledOrders, 1n);

  // Owner harvests 100% of accrued Aave V3 yield while remaining principal stays 999.75 USDC
  const ownerHarvestRecipient = "0x9999999999999999999999999999999999999999";
  const harvestTx = await chain.writeContract({
    from: accounts.owner.address,
    to: contracts.vault.address,
    abi: contracts.vault.abi,
    functionName: "harvestYield",
    args: [ownerHarvestRecipient],
  });
  assert.ok(harvestTx.result >= 2_400_000n, "Owner harvested full accrued Aave V3 interest");

  const remainingPrincipal = await chain.readContract({
    to: contracts.vault.address,
    abi: contracts.vault.abi,
    functionName: "principalDeposited",
  });
  assert.equal(remainingPrincipal, 999_750_000n);
});

test("2. True 86,400s Sliding Window Defeats Midnight-Boundary & Sybil Split-Order Attacks", async () => {
  const fixture = await deployFullProtocolFixture();
  const { chain, accounts, capabilities, contracts } = fixture;
  const { mandate, signature, allowlist } = await createStandardSignedMandate(fixture);
  const proof = allowlist.getProof(accounts.trustedProvider, capabilities.capMarketData);

  // Set timestamp right before UTC midnight (e.g., 23:59:30 UTC)
  const almostMidnight = BigInt(Math.floor(1_763_510_370 / 86_400) * 86_400 + 86_370);
  chain.setTimestamp(almostMidnight);

  // Spend 5 x 9.50 USDC = 47.50 USDC across the midnight boundary (3 before midnight, 2 after midnight)
  for (let i = 0; i < 5; i++) {
    chain.advanceTime(20); // Crosses 00:00:00 UTC cleanly without resetting rolling window!
    await chain.writeContract({
      from: accounts.agent.address,
      to: contracts.vault.address,
      abi: contracts.vault.abi,
      functionName: "settleX402Payment",
      args: [
        mandate,
        signature,
        "0x",
        {
          paymentNonce: keccak256(stringToHex(`split-tx-${i}`)),
          provider: accounts.trustedProvider,
          amount: 9_500_000n, // 9.50 USDC (< 10 USDC maxPerTx)
          resourceHash: keccak256(stringToHex(`/api/chunk/${i}`)),
          expectedPayloadHash: zeroHash,
          categoryHash: capabilities.capMarketData,
          merkleProof: proof,
          forceEscrow: false,
        },
      ],
    });
  }

  // 6th split order (+9.50 USDC -> 57.00 USDC > 50.00 USDC rolling 24h cap) MUST hard-revert!
  await assert.rejects(
    () =>
      chain.writeContract({
        from: accounts.agent.address,
        to: contracts.vault.address,
        abi: contracts.vault.abi,
        functionName: "settleX402Payment",
        args: [
          mandate,
          signature,
          "0x",
          {
            paymentNonce: keccak256(stringToHex("split-tx-6-overflow")),
            provider: accounts.trustedProvider,
            amount: 9_500_000n,
            resourceHash: keccak256(stringToHex("/api/chunk/6")),
            expectedPayloadHash: zeroHash,
            categoryHash: capabilities.capMarketData,
            merkleProof: proof,
            forceEscrow: false,
          },
        ],
      }),
    (err) => err.errorName === "Rolling24hWindowCapExceeded",
  );

  // Advance exactly 86,400s past the first slot -> oldest 9.50 USDC expires, freeing headroom!
  chain.advanceTime(86_400);
  const postWindowTx = await chain.writeContract({
    from: accounts.agent.address,
    to: contracts.vault.address,
    abi: contracts.vault.abi,
    functionName: "settleX402Payment",
    args: [
      mandate,
      signature,
      "0x",
      {
        paymentNonce: keccak256(stringToHex("split-tx-after-24h-expiry")),
        provider: accounts.trustedProvider,
        amount: 9_500_000n,
        resourceHash: keccak256(stringToHex("/api/chunk/post-expiry")),
        expectedPayloadHash: zeroHash,
        categoryHash: capabilities.capMarketData,
        merkleProof: proof,
        forceEscrow: false,
      },
    ],
  });
  assert.equal(postWindowTx.result, 6n, "9.50 USDC >= 5.00 USDC escrowThreshold creates escrow #6");
});

test("3. Optimistic Dispute Timelock Escrow: Freeze, Refund Re-Supply to Aave V3 & ERC-8004 Slashing", async () => {
  const fixture = await deployFullProtocolFixture();
  const { chain, accounts, capabilities, contracts } = fixture;
  const { mandate, signature, allowlist } = await createStandardSignedMandate(fixture);
  const proof = allowlist.getProof(accounts.trustedProvider, capabilities.capCompute);

  const expectedHash = sha256Hex('{"validDataset":true,"rows":1000}');
  const tamperedHash = sha256Hex('{"validDataset":false,"injected":"drain"}');

  // 6.00 USDC >= 5.00 USDC escrowThreshold -> routes automatically to EscrowStatus.Locked
  const lockTx = await chain.writeContract({
    from: accounts.agent.address,
    to: contracts.vault.address,
    abi: contracts.vault.abi,
    functionName: "settleX402Payment",
    args: [
      mandate,
      signature,
      "0x",
      {
        paymentNonce: keccak256(stringToHex("escrow-order-001")),
        provider: accounts.trustedProvider,
        amount: 6_000_000n,
        resourceHash: keccak256(stringToHex("/v1/dataset")),
        expectedPayloadHash: expectedHash,
        categoryHash: capabilities.capCompute,
        merkleProof: proof,
        forceEscrow: false,
      },
    ],
  });
  const escrowId = lockTx.result;
  assert.equal(escrowId, 1n);

  // Premature release before 1,800s timelock MUST revert with DisputeTimelockActive
  await assert.rejects(
    () =>
      chain.writeContract({
        from: accounts.trustedProvider,
        to: contracts.vault.address,
        abi: contracts.vault.abi,
        functionName: "releaseEscrow",
        args: [escrowId],
      }),
    (err) => err.errorName === "DisputeTimelockActive",
  );

  // Agent detects SHA-256 mismatch and freezes escrow on-chain
  await chain.writeContract({
    from: accounts.agent.address,
    to: contracts.vault.address,
    abi: contracts.vault.abi,
    functionName: "raiseDispute",
    args: [escrowId, tamperedHash, "SHA256_PAYLOAD_MISMATCH"],
  });

  // Arbitrator resolves in favor of Vault -> 6.00 USDC re-supplied directly to Aave V3 + provider slashed -1500 bps
  await chain.writeContract({
    from: accounts.arbitrator.address,
    to: contracts.vault.address,
    abi: contracts.vault.abi,
    functionName: "resolveDispute",
    args: [escrowId, true],
  });

  const restoredPrincipal = await chain.readContract({
    to: contracts.vault.address,
    abi: contracts.vault.abi,
    functionName: "principalDeposited",
  });
  assert.equal(restoredPrincipal, 1_000_000_000n, "Full 1,000 USDC principal restored in Aave V3");

  const slashedIdentity = await chain.readContract({
    to: contracts.registry.address,
    abi: contracts.registry.abi,
    functionName: "getAgentIdentity",
    args: [accounts.trustedProvider],
  });
  assert.equal(Number(slashedIdentity.reputationBps), 7_700, "9200 - 1500 = 7700 bps after dispute slash");
});

test("4. Dual-Track Rust Stylus Ed25519 Coprocessor End-to-End On-Chain Verification", async () => {
  const fixture = await deployFullProtocolFixture({ enableStylusPrecompile: true });
  const { chain, accounts, capabilities, contracts } = fixture;

  // Approve Stylus Ed25519 Coprocessor on MandateVault
  await chain.writeContract({
    from: accounts.owner.address,
    to: contracts.vault.address,
    abi: contracts.vault.abi,
    functionName: "setVerifierApproval",
    args: [STYLUS_COPROCESSOR_ADDRESS, true],
  });

  const allowlist = buildProviderAllowlistMerkleTree([
    { provider: accounts.trustedProvider, categoryHash: capabilities.capMarketData },
  ]);

  const stylusMandate = {
    mandateId: keccak256(stringToHex("stylus-ed25519-passkey-mandate")),
    agent: accounts.agent.address,
    maxPerTx: 8_000_000n,
    maxRolling24h: 40_000_000n,
    validAfter: 1_760_000_000n,
    deadline: 1_900_000_000n,
    minProviderReputationBps: 8_000,
    allowedProvidersRoot: allowlist.root,
    escrowThreshold: 5_000_000n,
    disputeWindowSeconds: 900n,
    verifierOverride: STYLUS_COPROCESSOR_ADDRESS,
  };

  const digest = await chain.readContract({
    to: contracts.vault.address,
    abi: contracts.vault.abi,
    functionName: "computeMandateDigest",
    args: [stylusMandate],
  });

  const ed25519Seed = keccak256(stringToHex("hardware-passkey-enclave-seed-01"));
  const signedEd = signStylusEd25519Mandate(ed25519Seed, digest);

  // Authorize the deterministic Ed25519-derived EVM authorizer identity on MandateVault
  await chain.writeContract({
    from: accounts.owner.address,
    to: contracts.vault.address,
    abi: contracts.vault.abi,
    functionName: "setDelegatedAuthorizer",
    args: [signedEd.authorizer, true],
  });

  // Valid Ed25519 mandate verified live by compiled Rust `stylus_verifier` settles atomically!
  const tx = await chain.writeContract({
    from: accounts.agent.address,
    to: contracts.vault.address,
    abi: contracts.vault.abi,
    functionName: "settleX402Payment",
    args: [
      stylusMandate,
      signedEd.signature,
      signedEd.pubkey,
      {
        paymentNonce: keccak256(stringToHex("stylus-ed25519-tx-1")),
        provider: accounts.trustedProvider,
        amount: 1_250_000n, // 1.25 USDC
        resourceHash: keccak256(stringToHex("/v1/enclave-inference")),
        expectedPayloadHash: zeroHash,
        categoryHash: capabilities.capMarketData,
        merkleProof: allowlist.getProof(accounts.trustedProvider, capabilities.capMarketData),
        forceEscrow: false,
      },
    ],
  });
  assert.equal(tx.result, 0n);

  // Tampering 1 bit in the Ed25519 signature MUST fail Stylus verification -> InvalidMandateSignature
  const corruptedSig = `0x${(BigInt(signedEd.signature.slice(0, 10)) ^ 1n).toString(16).padStart(8, "0")}${signedEd.signature.slice(10)}`;
  await assert.rejects(
    () =>
      chain.writeContract({
        from: accounts.agent.address,
        to: contracts.vault.address,
        abi: contracts.vault.abi,
        functionName: "settleX402Payment",
        args: [
          stylusMandate,
          corruptedSig,
          signedEd.pubkey,
          {
            paymentNonce: keccak256(stringToHex("stylus-ed25519-tx-bad")),
            provider: accounts.trustedProvider,
            amount: 1_250_000n,
            resourceHash: keccak256(stringToHex("/v1/enclave-inference")),
            expectedPayloadHash: zeroHash,
            categoryHash: capabilities.capMarketData,
            merkleProof: allowlist.getProof(accounts.trustedProvider, capabilities.capMarketData),
            forceEscrow: false,
          },
        ],
      }),
    (err) => err.errorName === "InvalidMandateSignature",
  );
});

test("5. 200 Red-Team Adversarial Procurement & Prompt-Injection Attack Vectors: 100.00% On-Chain Block Rate", async () => {
  const fixture = await deployFullProtocolFixture({
    initialPrincipalUsdc: 1_000_000_000n,
  });
  const { chain, accounts, capabilities, contracts } = fixture;
  const { mandate, signature, allowlist } = await createStandardSignedMandate(fixture);
  const validProof = allowlist.getProof(accounts.trustedProvider, capabilities.capMarketData);

  // Seed one legitimate 1.00 USDC payment so replay-nonce attacks have a real used nonce to target
  const usedNonce = keccak256(stringToHex("legit-seed-nonce-000"));
  await chain.writeContract({
    from: accounts.agent.address,
    to: contracts.vault.address,
    abi: contracts.vault.abi,
    functionName: "settleX402Payment",
    args: [
      mandate,
      signature,
      "0x",
      {
        paymentNonce: usedNonce,
        provider: accounts.trustedProvider,
        amount: 1_000_000n,
        resourceHash: keccak256(stringToHex("/seed")),
        expectedPayloadHash: zeroHash,
        categoryHash: capabilities.capMarketData,
        merkleProof: validProof,
        forceEscrow: false,
      },
    ],
  });

  // Saturate sliding window up to 49.00 / 50.00 USDC with 5 legitimate settlements (total = 1 + 48 = 49 USDC)
  for (let k = 0; k < 6; k++) {
    await chain.writeContract({
      from: accounts.agent.address,
      to: contracts.vault.address,
      abi: contracts.vault.abi,
      functionName: "settleX402Payment",
      args: [
        mandate,
        signature,
        "0x",
        {
          paymentNonce: keccak256(stringToHex(`legit-warmup-${k}`)),
          provider: accounts.trustedProvider,
          amount: 8_000_000n, // 6 * 8 = 48 USDC -> active window = 49.00 USDC
          resourceHash: keccak256(stringToHex(`/warmup/${k}`)),
          expectedPayloadHash: zeroHash,
          categoryHash: capabilities.capMarketData,
          merkleProof: validProof,
          forceEscrow: false,
        },
      ],
    });
  }

  const principalBeforeAttacks = await chain.readContract({
    to: contracts.vault.address,
    abi: contracts.vault.abi,
    functionName: "principalDeposited",
  });

  const attackerSignature = await signAp2Mandate({
    ownerPrivateKey: accounts.attackerKey,
    chainId: ARBITRUM_ONE_CHAIN_ID,
    vaultAddress: contracts.vault.address,
    mandate,
  });

  // Construct EIP-2 high-S malleable signature from valid signature
  const secp256k1Order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
  const rHex = signature.slice(0, 66);
  const sBig = BigInt(`0x${signature.slice(66, 130)}`);
  const vByte = Number(`0x${signature.slice(130, 132)}`);
  const highS = secp256k1Order - sBig;
  const flippedV = vByte === 27 ? 28 : 27;
  const malleableSig = concatHex([rHex, padHex(toHex(highS), { size: 32 }), toHex(flippedV, { size: 1 })]);

  let blockedCount = 0;
  const categoryBreakdown = {
    promptInjectionOverCap: 0,
    sybilSplit24hOverflow: 0,
    phishingAndLowReputation: 0,
    replayAndTemporalTamper: 0,
    forgedAndMalleableSignatures: 0,
  };

  // Vector Group A (50 vectors): Prompt-injected over-cap drains (10.01 USDC .. 999.00 USDC)
  for (let i = 0; i < 50; i++) {
    const drainAmount = 10_010_000n + BigInt(i) * 19_500_000n;
    await assert.rejects(
      () =>
        chain.writeContract({
          from: accounts.agent.address,
          to: contracts.vault.address,
          abi: contracts.vault.abi,
          functionName: "settleX402Payment",
          args: [
            mandate,
            signature,
            "0x",
            {
              paymentNonce: keccak256(stringToHex(`atk-overcap-${i}`)),
              provider: accounts.trustedProvider,
              amount: drainAmount,
              resourceHash: keccak256(stringToHex(`/inject/overcap/${i}`)),
              expectedPayloadHash: zeroHash,
              categoryHash: capabilities.capMarketData,
              merkleProof: validProof,
              forceEscrow: false,
            },
          ],
        }),
      (err) => err.errorName === "PerTxCapExceeded",
    );
    blockedCount++;
    categoryBreakdown.promptInjectionOverCap++;
  }

  // Vector Group B (50 vectors): Sub-per-tx-cap Sybil split-order bursts breaching 50 USDC 24h sliding window
  for (let i = 0; i < 50; i++) {
    const splitAmount = 1_000_001n + BigInt(i) * 150_000n; // > 1.00 USDC remaining headroom, <= 10.00 USDC per-tx cap
    await assert.rejects(
      () =>
        chain.writeContract({
          from: accounts.agent.address,
          to: contracts.vault.address,
          abi: contracts.vault.abi,
          functionName: "settleX402Payment",
          args: [
            mandate,
            signature,
            "0x",
            {
              paymentNonce: keccak256(stringToHex(`atk-sybil-${i}`)),
              provider: accounts.trustedProvider,
              amount: splitAmount,
              resourceHash: keccak256(stringToHex(`/inject/sybil/${i}`)),
              expectedPayloadHash: zeroHash,
              categoryHash: capabilities.capMarketData,
              merkleProof: validProof,
              forceEscrow: false,
            },
          ],
        }),
      (err) => err.errorName === "Rolling24hWindowCapExceeded",
    );
    blockedCount++;
    categoryBreakdown.sybilSplit24hOverflow++;
  }

  // Vector Group C (40 vectors): Phishing lookalike addresses & low-ERC8004-reputation providers
  const openAllowlistMandate = { ...mandate, allowedProvidersRoot: zeroHash };
  const openAllowlistSig = await signAp2Mandate({
    ownerPrivateKey: accounts.ownerKey,
    chainId: ARBITRUM_ONE_CHAIN_ID,
    vaultAddress: contracts.vault.address,
    mandate: openAllowlistMandate,
  });

  for (let i = 0; i < 40; i++) {
    const isMerkleBypass = i < 20;
    await assert.rejects(
      () =>
        chain.writeContract({
          from: accounts.agent.address,
          to: contracts.vault.address,
          abi: contracts.vault.abi,
          functionName: "settleX402Payment",
          args: [
            isMerkleBypass ? mandate : openAllowlistMandate,
            isMerkleBypass ? signature : openAllowlistSig,
            "0x",
            {
              paymentNonce: keccak256(stringToHex(`atk-provider-${i}`)),
              provider: isMerkleBypass ? accounts.phishingAddress : accounts.lowRepProvider,
              amount: 500_000n,
              resourceHash: keccak256(stringToHex(`/inject/phishing/${i}`)),
              expectedPayloadHash: zeroHash,
              categoryHash: capabilities.capMarketData,
              merkleProof: validProof,
              forceEscrow: false,
            },
          ],
        }),
      (err) =>
        isMerkleBypass
          ? err.errorName === "UnauthorizedProvider"
          : err.errorName === "InsufficientProviderReputation",
    );
    blockedCount++;
    categoryBreakdown.phishingAndLowReputation++;
  }

  // Vector Group D (30 vectors): Nonce replay, unauthorized callerhijack, dust spam, expired/future mandates
  const expiredMandate = { ...mandate, mandateId: keccak256(stringToHex("exp")), deadline: 1_700_000_000n };
  const expiredSig = await signAp2Mandate({
    ownerPrivateKey: accounts.ownerKey,
    chainId: ARBITRUM_ONE_CHAIN_ID,
    vaultAddress: contracts.vault.address,
    mandate: expiredMandate,
  });

  for (let i = 0; i < 30; i++) {
    const mode = i % 3;
    await assert.rejects(
      () =>
        chain.writeContract({
          from: mode === 1 ? accounts.attacker.address : accounts.agent.address,
          to: contracts.vault.address,
          abi: contracts.vault.abi,
          functionName: "settleX402Payment",
          args: [
            mode === 2 ? expiredMandate : mandate,
            mode === 2 ? expiredSig : signature,
            "0x",
            {
              paymentNonce: mode === 0 ? usedNonce : keccak256(stringToHex(`atk-temporal-${i}`)),
              provider: accounts.trustedProvider,
              amount: 500_000n,
              resourceHash: keccak256(stringToHex(`/inject/replay/${i}`)),
              expectedPayloadHash: zeroHash,
              categoryHash: capabilities.capMarketData,
              merkleProof: validProof,
              forceEscrow: false,
            },
          ],
        }),
      (err) =>
        ["PaymentNonceAlreadyUsed", "CallerNotAuthorizedAgent", "MandateExpired"].includes(err.errorName),
    );
    blockedCount++;
    categoryBreakdown.replayAndTemporalTamper++;
  }

  // Vector Group E (30 vectors): Forged attacker signer, EIP-2 high-S malleable signature, tampered limit with old sig
  for (let i = 0; i < 30; i++) {
    const mode = i % 3;
    const tamperedMandate = mode === 2 ? { ...mandate, maxPerTx: 999_000_000n } : mandate;
    const badSig = mode === 0 ? attackerSignature : mode === 1 ? malleableSig : signature;

    await assert.rejects(
      () =>
        chain.writeContract({
          from: accounts.agent.address,
          to: contracts.vault.address,
          abi: contracts.vault.abi,
          functionName: "settleX402Payment",
          args: [
            tamperedMandate,
            badSig,
            "0x",
            {
              paymentNonce: keccak256(stringToHex(`atk-sig-${i}`)),
              provider: accounts.trustedProvider,
              amount: 500_000n,
              resourceHash: keccak256(stringToHex(`/inject/sig/${i}`)),
              expectedPayloadHash: zeroHash,
              categoryHash: capabilities.capMarketData,
              merkleProof: validProof,
              forceEscrow: false,
            },
          ],
        }),
      (err) => err.errorName === "InvalidMandateSignature",
    );
    blockedCount++;
    categoryBreakdown.forgedAndMalleableSignatures++;
  }

  const principalAfterAttacks = await chain.readContract({
    to: contracts.vault.address,
    abi: contracts.vault.abi,
    functionName: "principalDeposited",
  });

  assert.equal(blockedCount, 200, "All 200 adversarial vectors executed and deterministically blocked");
  assert.equal(
    principalAfterAttacks,
    principalBeforeAttacks,
    "0.000000 USDC unauthorized capital leaked across 200 attacks",
  );
  console.log(`[red-team] 200/200 adversarial vectors blocked (100.00%) | Breakdown:`, categoryBreakdown);
});
