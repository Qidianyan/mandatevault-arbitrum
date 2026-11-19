import assert from "node:assert/strict";
import test from "node:test";
import {
  concatHex,
  encodeAbiParameters,
  encodeFunctionData,
  encodePacked,
  keccak256,
  padHex,
  stringToHex,
  toHex,
  zeroAddress,
  zeroHash,
} from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import {
  ARBITRUM_ONE_CHAIN_ID,
  buildProviderAllowlistMerkleTree,
  sha256Hex,
  signAp2Mandate,
} from "../sdk/typescript/index.ts";
import {
  STYLUS_COPROCESSOR_ADDRESS,
  deployFullProtocolFixture,
  signStylusEd25519Mandate,
} from "./evm_harness.mjs";

const SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const ERC1271_MAGIC_VALUE = "0x1626ba7e";
const ERC1271_INVALID = "0xffffffff";
const VALIDATION_FAILED = 1n;
const EXEC_MODE_SINGLE_DEFAULT = zeroHash;

const SESSION_INIT_CONFIG_PARAM = [
  {
    type: "tuple",
    components: [
      { name: "mandateVault", type: "address" },
      { name: "sessionKey", type: "address" },
      { name: "boundMandateId", type: "bytes32" },
      { name: "maxPerTx", type: "uint256" },
      { name: "maxRolling24h", type: "uint256" },
      { name: "validAfter", type: "uint48" },
      { name: "validUntil", type: "uint48" },
      { name: "minProviderReputationBps", type: "uint16" },
      { name: "allowedProvidersRoot", type: "bytes32" },
      { name: "allowDisputeFiling", type: "bool" },
    ],
  },
];

function encodeSessionInit(cfg) {
  return encodeAbiParameters(SESSION_INIT_CONFIG_PARAM, [cfg]);
}

function buildSingleExecCallData(kernelAbi, target, value, innerCallData, mode = EXEC_MODE_SINGLE_DEFAULT) {
  const executionCalldata = encodePacked(
    ["address", "uint256", "bytes"],
    [target, BigInt(value), innerCallData],
  );
  return encodeFunctionData({
    abi: kernelAbi,
    functionName: "execute",
    args: [mode, executionCalldata],
  });
}

function makePackedUserOp({ sender, callData, signature = "0x", nonce = 0n }) {
  return {
    sender,
    nonce,
    initCode: "0x",
    callData,
    accountGasLimits: zeroHash,
    preVerificationGas: 50_000n,
    gasFees: zeroHash,
    paymasterAndData: "0x",
    signature,
  };
}

function malleateSignature(sigHex) {
  const raw = sigHex.slice(2);
  const r = raw.slice(0, 64);
  const s = BigInt(`0x${raw.slice(64, 128)}`);
  const v = parseInt(raw.slice(128, 130), 16);
  const highS = (SECP256K1_N - s).toString(16).padStart(64, "0");
  const flippedV = (v === 27 ? 28 : 27).toString(16).padStart(2, "0");
  return `0x${r}${highS}${flippedV}`;
}

async function deployZeroDevFixture(opts = {}) {
  const fixture = await deployFullProtocolFixture(opts);
  const { chain, accounts, capabilities, contracts } = fixture;

  const sessionKeyPriv = generatePrivateKey();
  const sessionKeyBPriv = generatePrivateKey();
  const sessionKey = privateKeyToAccount(sessionKeyPriv);
  const sessionKeyB = privateKeyToAccount(sessionKeyBPriv);

  const entryPoint = await chain.deployContract({
    from: accounts.owner.address,
    artifactName: "ReferenceEntryPointV07",
  });

  const validator = await chain.deployContract({
    from: accounts.owner.address,
    artifactName: "ZeroDevMandateValidator",
  });

  const kernel = await chain.deployContract({
    from: accounts.owner.address,
    artifactName: "ReferenceKernelV3Account",
    args: [accounts.owner.address, entryPoint.address],
  });

  const allowlist = buildProviderAllowlistMerkleTree([
    { provider: accounts.trustedProvider, categoryHash: capabilities.capMarketData },
    { provider: accounts.trustedProvider, categoryHash: capabilities.capCompute },
    { provider: accounts.secondaryProvider, categoryHash: capabilities.capCompute },
  ]);

  const mandateId = keccak256(stringToHex("zerodev-kernel-erc7579-mandate-v1"));
  const mandate = {
    mandateId,
    agent: kernel.address,
    maxPerTx: 10_000_000n, // 10.00 USDC
    maxRolling24h: 25_000_000n, // 25.00 USDC
    validAfter: 1_760_000_000n,
    deadline: 1_900_000_000n,
    minProviderReputationBps: 8_000,
    allowedProvidersRoot: allowlist.root,
    escrowThreshold: 5_000_000n, // 5.00 USDC
    disputeWindowSeconds: 1_800n,
    verifierOverride: zeroAddress,
  };

  const mandateSignature = await signAp2Mandate({
    ownerPrivateKey: accounts.ownerKey,
    chainId: ARBITRUM_ONE_CHAIN_ID,
    vaultAddress: contracts.vault.address,
    mandate,
  });

  const defaultSessionConfig = {
    mandateVault: contracts.vault.address,
    sessionKey: sessionKey.address,
    boundMandateId: mandateId,
    maxPerTx: 10_000_000n,
    maxRolling24h: 25_000_000n,
    validAfter: 1_760_000_000,
    validUntil: 1_890_000_000,
    minProviderReputationBps: 8_000,
    allowedProvidersRoot: allowlist.root,
    allowDisputeFiling: true,
  };

  return {
    ...fixture,
    sessionKeyPriv,
    sessionKeyBPriv,
    sessionKey,
    sessionKeyB,
    entryPoint,
    validator,
    kernel,
    allowlist,
    mandateId,
    mandate,
    mandateSignature,
    defaultSessionConfig,
  };
}

function buildSettleCallData(vaultAbi, mandate, mandateSignature, verifierContext, req) {
  return encodeFunctionData({
    abi: vaultAbi,
    functionName: "settleX402Payment",
    args: [mandate, mandateSignature, verifierContext, req],
  });
}

test("1. ERC-7579 Module Introspection (isModuleType), Lifecycle (onInstall/onUninstall), & Epoch Anti-Resurrection", async () => {
  const ctx = await deployZeroDevFixture();
  const { chain, accounts, contracts, validator, kernel, defaultSessionConfig, sessionKey, sessionKeyB, sessionKeyPriv, mandate, mandateSignature, allowlist, capabilities } = ctx;

  // Verify ERC-7579 module type checks: ONLY Type 1 (Validator) returns true
  assert.equal(await chain.readContract({ to: validator.address, abi: validator.abi, functionName: "isModuleType", args: [1n] }), true);
  assert.equal(await chain.readContract({ to: validator.address, abi: validator.abi, functionName: "isModuleType", args: [2n] }), false);
  assert.equal(await chain.readContract({ to: validator.address, abi: validator.abi, functionName: "isModuleType", args: [3n] }), false);
  assert.equal(await chain.readContract({ to: validator.address, abi: validator.abi, functionName: "isModuleType", args: [4n] }), false);
  assert.equal(await chain.readContract({ to: validator.address, abi: validator.abi, functionName: "isModuleType", args: [0n] }), false);
  assert.equal(await chain.readContract({ to: validator.address, abi: validator.abi, functionName: "isModuleType", args: [99n] }), false);

  const scheme = await chain.readContract({ to: validator.address, abi: validator.abi, functionName: "validatorScheme" });
  assert.equal(scheme, "ZERODEV-KERNEL-ERC7579-MANDATE-VALIDATOR-V1");

  assert.equal(await chain.readContract({ to: validator.address, abi: validator.abi, functionName: "isInitialized", args: [kernel.address] }), false);

  // Attempting to install validator as Executor (type 2) reverts
  await assert.rejects(
    () => chain.writeContract({
      from: accounts.owner.address,
      to: kernel.address,
      abi: kernel.abi,
      functionName: "installModule",
      args: [2n, validator.address, encodeSessionInit(defaultSessionConfig)],
    }),
    (err) => err.errorName === "UnsupportedModuleType",
  );

  // Invalid config checks: maxPerTx > maxRolling24h, bps > 10_000, validUntil <= validAfter, zero address
  await assert.rejects(
    () => chain.writeContract({
      from: accounts.owner.address,
      to: kernel.address,
      abi: kernel.abi,
      functionName: "installModule",
      args: [1n, validator.address, encodeSessionInit({ ...defaultSessionConfig, maxPerTx: 30_000_000n, maxRolling24h: 25_000_000n })],
    }),
    (err) => err.errorName === "InvalidSessionCaps",
  );
  await assert.rejects(
    () => chain.writeContract({
      from: accounts.owner.address,
      to: kernel.address,
      abi: kernel.abi,
      functionName: "installModule",
      args: [1n, validator.address, encodeSessionInit({ ...defaultSessionConfig, minProviderReputationBps: 10_001 })],
    }),
    (err) => err.errorName === "InvalidReputationThreshold",
  );
  await assert.rejects(
    () => chain.writeContract({
      from: accounts.owner.address,
      to: kernel.address,
      abi: kernel.abi,
      functionName: "installModule",
      args: [1n, validator.address, encodeSessionInit({ ...defaultSessionConfig, validAfter: 2_000_000_000, validUntil: 1_900_000_000 })],
    }),
    (err) => err.errorName === "InvalidValidityWindow",
  );
  await assert.rejects(
    () => chain.writeContract({
      from: accounts.owner.address,
      to: kernel.address,
      abi: kernel.abi,
      functionName: "installModule",
      args: [1n, validator.address, encodeSessionInit({ ...defaultSessionConfig, sessionKey: zeroAddress })],
    }),
    (err) => err.errorName === "InvalidZeroAddress",
  );

  // Clean install (Epoch 1)
  await chain.writeContract({
    from: accounts.owner.address,
    to: kernel.address,
    abi: kernel.abi,
    functionName: "installModule",
    args: [1n, validator.address, encodeSessionInit(defaultSessionConfig)],
  });
  assert.equal(await chain.readContract({ to: validator.address, abi: validator.abi, functionName: "isInitialized", args: [kernel.address] }), true);

  const acctCfg1 = await chain.readContract({ to: validator.address, abi: validator.abi, functionName: "getAccountConfig", args: [kernel.address] });
  assert.equal(acctCfg1[0], true);
  assert.equal(acctCfg1[1], 1n);
  assert.equal(acctCfg1[2].toLowerCase(), contracts.vault.address.toLowerCase());
  assert.equal(acctCfg1[3].toLowerCase(), sessionKey.address.toLowerCase());

  // Double install reverts AlreadyInitialized
  await assert.rejects(
    () => chain.writeContract({
      from: accounts.owner.address,
      to: kernel.address,
      abi: kernel.abi,
      functionName: "installModule",
      args: [1n, validator.address, encodeSessionInit(defaultSessionConfig)],
    }),
    (err) => err.errorName === "AlreadyInitialized",
  );

  // Uninstall & Re-install with Session Key B (Epoch 2) -> Epoch 1 Session Key A MUST NOT resurrect!
  await chain.writeContract({
    from: accounts.owner.address,
    to: kernel.address,
    abi: kernel.abi,
    functionName: "uninstallModule",
    args: [1n, validator.address, "0x"],
  });
  assert.equal(await chain.readContract({ to: validator.address, abi: validator.abi, functionName: "isInitialized", args: [kernel.address] }), false);

  await chain.writeContract({
    from: accounts.owner.address,
    to: kernel.address,
    abi: kernel.abi,
    functionName: "installModule",
    args: [1n, validator.address, encodeSessionInit({ ...defaultSessionConfig, sessionKey: sessionKeyB.address })],
  });
  const acctCfg2 = await chain.readContract({ to: validator.address, abi: validator.abi, functionName: "getAccountConfig", args: [kernel.address] });
  assert.equal(acctCfg2[1], 2n, "installEpoch increments to 2 on reinstall");

  // Sign a UserOp with stale Epoch 1 sessionKey -> MUST return VALIDATION_FAILED (1)
  const settleCall = buildSettleCallData(contracts.vault.abi, mandate, mandateSignature, "0x", {
    paymentNonce: keccak256(stringToHex("epoch-stale-check")),
    provider: accounts.trustedProvider,
    amount: 500_000n,
    resourceHash: keccak256(stringToHex("/v1/stale-check")),
    expectedPayloadHash: zeroHash,
    categoryHash: capabilities.capMarketData,
    merkleProof: allowlist.getProof(accounts.trustedProvider, capabilities.capMarketData),
    forceEscrow: false,
  });
  const opCallData = buildSingleExecCallData(kernel.abi, contracts.vault.address, 0n, settleCall);
  const userOpHash = keccak256(stringToHex("userop-stale-epoch1"));
  const staleSig = await sessionKey.sign({ hash: userOpHash });
  const staleOp = makePackedUserOp({ sender: kernel.address, callData: opCallData, signature: staleSig });

  const validationResult = await chain.readContract({
    from: kernel.address,
    to: validator.address,
    abi: validator.abi,
    functionName: "validateUserOp",
    args: [staleOp, userOpHash],
  });
  assert.equal(validationResult, VALIDATION_FAILED, "Stale epoch-1 session key must be rejected with VALIDATION_FAILED");
});

test("2. End-to-End ZeroDev Kernel v3.1 UserOp Settlement -> Aave V3 Zero-Idle Yield + ERC-1271 Signature Validation", async () => {
  const ctx = await deployZeroDevFixture({ initialPrincipalUsdc: 1_000_000_000n });
  const { chain, accounts, capabilities, contracts, entryPoint, validator, kernel, allowlist, mandate, mandateSignature, defaultSessionConfig, sessionKey, sessionKeyPriv } = ctx;

  await chain.writeContract({
    from: accounts.owner.address,
    to: kernel.address,
    abi: kernel.abi,
    functionName: "installModule",
    args: [1n, validator.address, encodeSessionInit(defaultSessionConfig)],
  });

  // Accrue 30 days of Aave V3 yield (~2.50 USDC on 1,000 USDC)
  chain.advanceTime(30 * 86_400);

  // 2A. Raw userOpHash signature executed via EntryPoint v0.7 -> Kernel v3.1 -> ZeroDevMandateValidator -> MandateVault -> Aave V3
  const proof = allowlist.getProof(accounts.trustedProvider, capabilities.capMarketData);
  const settleInner = buildSettleCallData(contracts.vault.abi, mandate, mandateSignature, "0x", {
    paymentNonce: keccak256(stringToHex("zd-userop-001")),
    provider: accounts.trustedProvider,
    amount: 750_000n, // 0.75 USDC
    resourceHash: keccak256(stringToHex("/v1/arb-market-feed")),
    expectedPayloadHash: zeroHash,
    categoryHash: capabilities.capMarketData,
    merkleProof: proof,
    forceEscrow: false,
  });
  const callData = buildSingleExecCallData(kernel.abi, contracts.vault.address, 0n, settleInner);
  const userOpHash1 = keccak256(stringToHex("entryPoint-userOpHash-001"));
  const sig1 = await sessionKey.sign({ hash: userOpHash1 });
  const op1 = makePackedUserOp({ sender: kernel.address, callData, signature: sig1, nonce: 1n });

  const handleTx = await chain.writeContract({
    from: accounts.owner.address,
    to: entryPoint.address,
    abi: entryPoint.abi,
    functionName: "handleSingleOp",
    args: [op1, userOpHash1],
  });

  // Verify packed ERC-4337 ValidationData returns authorizer=0x0 and intersected [validAfter, validUntil]
  const parsedVd = await chain.readContract({
    to: validator.address,
    abi: validator.abi,
    functionName: "parseValidationData",
    args: [handleTx.result[0]],
  });
  assert.equal(parsedVd[0], zeroAddress);
  assert.equal(Number(parsedVd[1]), 1_890_000_000, "validUntil = min(session 1.89B, mandate 1.90B)");
  assert.equal(Number(parsedVd[2]), 1_760_000_000, "validAfter = max(session 1.76B, mandate 1.76B)");

  // Verify provider paid & ERC-8004 reputation increased +25 bps (9200 -> 9225)
  assert.equal(
    await chain.readContract({ to: contracts.usdc.address, abi: contracts.usdc.abi, functionName: "balanceOf", args: [accounts.trustedProvider] }),
    750_000n,
  );
  const provId = await chain.readContract({ to: contracts.registry.address, abi: contracts.registry.abi, functionName: "getAgentIdentity", args: [accounts.trustedProvider] });
  assert.equal(Number(provId.reputationBps), 9_225);

  // 2B. EIP-191 eth_sign prefixed signature (ZeroDev SDK / personal_sign compatibility)
  const settleInner2 = buildSettleCallData(contracts.vault.abi, mandate, mandateSignature, "0x", {
    paymentNonce: keccak256(stringToHex("zd-userop-002-eip191")),
    provider: accounts.trustedProvider,
    amount: 250_000n,
    resourceHash: keccak256(stringToHex("/v1/arb-market-feed-2")),
    expectedPayloadHash: zeroHash,
    categoryHash: capabilities.capMarketData,
    merkleProof: proof,
    forceEscrow: false,
  });
  const callData2 = buildSingleExecCallData(kernel.abi, contracts.vault.address, 0n, settleInner2);
  const userOpHash2 = keccak256(stringToHex("entryPoint-userOpHash-002-eip191"));
  const sig2 = await sessionKey.signMessage({ message: { raw: userOpHash2 } });
  const op2 = makePackedUserOp({ sender: kernel.address, callData: callData2, signature: sig2, nonce: 2n });

  await chain.writeContract({
    from: accounts.owner.address,
    to: entryPoint.address,
    abi: entryPoint.abi,
    functionName: "handleSingleOp",
    args: [op2, userOpHash2],
  });
  assert.equal(
    await chain.readContract({ to: contracts.usdc.address, abi: contracts.usdc.abi, functionName: "balanceOf", args: [accounts.trustedProvider] }),
    1_000_000n,
  );

  // Owner harvests 100% of Aave V3 yield while principal remains exactly 999.00 USDC
  const yieldRecipient = "0x8888888888888888888888888888888888888888";
  const harvestTx = await chain.writeContract({
    from: accounts.owner.address,
    to: contracts.vault.address,
    abi: contracts.vault.abi,
    functionName: "harvestYield",
    args: [yieldRecipient],
  });
  assert.ok(harvestTx.result >= 2_400_000n, "Owner harvests ring-fenced Aave V3 interest");
  assert.equal(
    await chain.readContract({ to: contracts.vault.address, abi: contracts.vault.abi, functionName: "principalDeposited" }),
    999_000_000n,
  );

  // 2C. ERC-1271 isValidSignature -> isValidSignatureWithSender checks
  const digest = keccak256(stringToHex("x402-erc1271-auth-challenge"));
  const valid1271Sig = await sessionKey.sign({ hash: digest });
  const malleable1271Sig = malleateSignature(valid1271Sig);
  const attacker1271Sig = await accounts.attacker.sign({ hash: digest });

  assert.equal(
    await chain.readContract({ to: kernel.address, abi: kernel.abi, functionName: "isValidSignature", args: [digest, valid1271Sig] }),
    ERC1271_MAGIC_VALUE,
  );
  assert.equal(
    await chain.readContract({ to: kernel.address, abi: kernel.abi, functionName: "isValidSignature", args: [digest, malleable1271Sig] }),
    ERC1271_INVALID,
  );
  assert.equal(
    await chain.readContract({ to: kernel.address, abi: kernel.abi, functionName: "isValidSignature", args: [digest, attacker1271Sig] }),
    ERC1271_INVALID,
  );

  // When vault is paused, ERC-1271 session key signature immediately returns ERC1271_INVALID
  await chain.writeContract({ from: accounts.owner.address, to: contracts.vault.address, abi: contracts.vault.abi, functionName: "setPaused", args: [true] });
  assert.equal(
    await chain.readContract({ to: kernel.address, abi: kernel.abi, functionName: "isValidSignature", args: [digest, valid1271Sig] }),
    ERC1271_INVALID,
  );
  await chain.writeContract({ from: accounts.owner.address, to: contracts.vault.address, abi: contracts.vault.abi, functionName: "setPaused", args: [false] });
  assert.equal(
    await chain.readContract({ to: kernel.address, abi: kernel.abi, functionName: "isValidSignature", args: [digest, valid1271Sig] }),
    ERC1271_MAGIC_VALUE,
  );
});

test("3. Live Rolling-24h Cap Sync Across UTC Midnight + Multi-Session Rotation/Revocation + Defensive Escrow Dispute", async () => {
  const ctx = await deployZeroDevFixture();
  const { chain, accounts, capabilities, contracts, entryPoint, validator, kernel, allowlist, mandate, mandateSignature, defaultSessionConfig, sessionKey, sessionKeyB } = ctx;

  await chain.writeContract({
    from: accounts.owner.address,
    to: kernel.address,
    abi: kernel.abi,
    functionName: "installModule",
    args: [1n, validator.address, encodeSessionInit(defaultSessionConfig)],
  });

  // Set clock to 23:59:30 UTC
  const almostMidnight = BigInt(Math.floor(1_763_510_370 / 86_400) * 86_400 + 86_370);
  chain.setTimestamp(almostMidnight);
  const proof = allowlist.getProof(accounts.trustedProvider, capabilities.capCompute);

  // Spend 2 x 10.00 USDC = 20.00 USDC across UTC midnight (session maxRolling24h = 25.00 USDC)
  for (let i = 0; i < 2; i++) {
    chain.advanceTime(45); // Crosses 00:00:00 UTC on 2nd tx!
    const inner = buildSettleCallData(contracts.vault.abi, mandate, mandateSignature, "0x", {
      paymentNonce: keccak256(stringToHex(`zd-rolling-${i}`)),
      provider: accounts.trustedProvider,
      amount: 10_000_000n,
      resourceHash: keccak256(stringToHex(`/v1/gpu/${i}`)),
      expectedPayloadHash: sha256Hex(`expected-payload-${i}`),
      categoryHash: capabilities.capCompute,
      merkleProof: proof,
      forceEscrow: false,
    });
    const opCallData = buildSingleExecCallData(kernel.abi, contracts.vault.address, 0n, inner);
    const opHash = keccak256(stringToHex(`op-rolling-${i}`));
    const sig = await sessionKey.sign({ hash: opHash });
    await chain.writeContract({
      from: accounts.owner.address,
      to: entryPoint.address,
      abi: entryPoint.abi,
      functionName: "handleSingleOp",
      args: [makePackedUserOp({ sender: kernel.address, callData: opCallData, signature: sig, nonce: BigInt(i) }), opHash],
    });
  }

  // 3rd UserOp for 6.00 USDC (20 + 6 = 26 > 25 USDC rolling 24h cap) MUST fail right inside validateUserOp!
  const overflowInner = buildSettleCallData(contracts.vault.abi, mandate, mandateSignature, "0x", {
    paymentNonce: keccak256(stringToHex("zd-rolling-overflow")),
    provider: accounts.trustedProvider,
    amount: 6_000_000n,
    resourceHash: keccak256(stringToHex("/v1/gpu/overflow")),
    expectedPayloadHash: zeroHash,
    categoryHash: capabilities.capCompute,
    merkleProof: proof,
    forceEscrow: false,
  });
  const overflowCallData = buildSingleExecCallData(kernel.abi, contracts.vault.address, 0n, overflowInner);
  const overflowHash = keccak256(stringToHex("op-rolling-overflow"));
  const overflowSig = await sessionKey.sign({ hash: overflowHash });

  await assert.rejects(
    () => chain.writeContract({
      from: accounts.owner.address,
      to: entryPoint.address,
      abi: entryPoint.abi,
      functionName: "handleSingleOp",
      args: [makePackedUserOp({ sender: kernel.address, callData: overflowCallData, signature: overflowSig, nonce: 2n }), overflowHash],
    }),
    (err) => err.errorName === "SessionRolling24hCapExceeded",
  );

  // Defensive raiseDispute on Escrow #1 (10 USDC >= 5 USDC threshold) via session key succeeds when allowDisputeFiling = true
  const disputeInner = encodeFunctionData({
    abi: contracts.vault.abi,
    functionName: "raiseDispute",
    args: [1n, sha256Hex("tampered-gpu-output"), "SHA-256 mismatch detected by autonomous agent"],
  });
  const disputeCallData = buildSingleExecCallData(kernel.abi, contracts.vault.address, 0n, disputeInner);
  const disputeHash = keccak256(stringToHex("op-raise-dispute-1"));
  const disputeSig = await sessionKey.sign({ hash: disputeHash });
  await chain.writeContract({
    from: accounts.owner.address,
    to: entryPoint.address,
    abi: entryPoint.abi,
    functionName: "handleSingleOp",
    args: [makePackedUserOp({ sender: kernel.address, callData: disputeCallData, signature: disputeSig, nonce: 3n }), disputeHash],
  });
  const escrow1 = await chain.readContract({ to: contracts.vault.address, abi: contracts.vault.abi, functionName: "escrows", args: [1n] });
  assert.equal(Number(escrow1[9]), 2, "Escrow #1 transitioned to EscrowStatus.Disputed");

  // Register secondary session key B with allowDisputeFiling = false, then revoke primary sessionKey
  const regData = encodeFunctionData({
    abi: validator.abi,
    functionName: "registerSessionKey",
    args: [{ ...defaultSessionConfig, sessionKey: sessionKeyB.address, allowDisputeFiling: false }],
  });
  await chain.writeContract({
    from: accounts.owner.address,
    to: kernel.address,
    abi: kernel.abi,
    functionName: "executeOwnerCall",
    args: [validator.address, regData],
  });

  // Session Key B CANNOT call raiseDispute when allowDisputeFiling = false
  const dispute2Inner = encodeFunctionData({
    abi: contracts.vault.abi,
    functionName: "raiseDispute",
    args: [2n, sha256Hex("bad"), "unauthorized dispute attempt"],
  });
  const dispute2CallData = buildSingleExecCallData(kernel.abi, contracts.vault.address, 0n, dispute2Inner);
  const dispute2Hash = keccak256(stringToHex("op-raise-dispute-2-blocked"));
  const dispute2SigB = await sessionKeyB.sign({ hash: dispute2Hash });
  await assert.rejects(
    () => chain.writeContract({
      from: accounts.owner.address,
      to: entryPoint.address,
      abi: entryPoint.abi,
      functionName: "handleSingleOp",
      args: [makePackedUserOp({ sender: kernel.address, callData: dispute2CallData, signature: dispute2SigB, nonce: 4n }), dispute2Hash],
    }),
    (err) => err.errorName === "DisallowedSelector",
  );

  // Revoke original sessionKey -> immediately rejected by validateUserOp & EntryPoint (AA24SignatureError)
  const revokeData = encodeFunctionData({
    abi: validator.abi,
    functionName: "revokeSessionKey",
    args: [sessionKey.address],
  });
  await chain.writeContract({
    from: accounts.owner.address,
    to: kernel.address,
    abi: kernel.abi,
    functionName: "executeOwnerCall",
    args: [validator.address, revokeData],
  });

  // Advance full 86,400s so rolling window expires
  chain.advanceTime(86_400);

  // Revoked sessionKey STILL fails even after rolling window resets
  const postExpiryInner = buildSettleCallData(contracts.vault.abi, mandate, mandateSignature, "0x", {
    paymentNonce: keccak256(stringToHex("zd-after-86400s")),
    provider: accounts.trustedProvider,
    amount: 4_000_000n,
    resourceHash: keccak256(stringToHex("/v1/gpu/post-window")),
    expectedPayloadHash: zeroHash,
    categoryHash: capabilities.capCompute,
    merkleProof: proof,
    forceEscrow: false,
  });
  const postExpiryCallData = buildSingleExecCallData(kernel.abi, contracts.vault.address, 0n, postExpiryInner);
  const postExpiryHash = keccak256(stringToHex("op-post-window"));
  const revokedSig = await sessionKey.sign({ hash: postExpiryHash });

  await assert.rejects(
    () => chain.writeContract({
      from: accounts.owner.address,
      to: entryPoint.address,
      abi: entryPoint.abi,
      functionName: "handleSingleOp",
      args: [makePackedUserOp({ sender: kernel.address, callData: postExpiryCallData, signature: revokedSig, nonce: 5n }), postExpiryHash],
    }),
    (err) => err.errorName === "AA24SignatureError",
  );

  // Active rotated Session Key B succeeds cleanly after 86,400s window expiry!
  const validSigB = await sessionKeyB.sign({ hash: postExpiryHash });
  await chain.writeContract({
    from: accounts.owner.address,
    to: entryPoint.address,
    abi: entryPoint.abi,
    functionName: "handleSingleOp",
    args: [makePackedUserOp({ sender: kernel.address, callData: postExpiryCallData, signature: validSigB, nonce: 6n }), postExpiryHash],
  });
});

test("4. Exhaustive ZeroDev / ERC-7579 Adversarial Attack Rejection Matrix (22 Distinct Attack Vectors)", async () => {
  const ctx = await deployZeroDevFixture({ initialPrincipalUsdc: 50_000_000n }); // 50 USDC principal
  const { chain, accounts, capabilities, contracts, entryPoint, validator, kernel, allowlist, mandate, mandateSignature, defaultSessionConfig, sessionKey } = ctx;

  await chain.writeContract({
    from: accounts.owner.address,
    to: kernel.address,
    abi: kernel.abi,
    functionName: "installModule",
    args: [1n, validator.address, encodeSessionInit(defaultSessionConfig)],
  });

  const validProof = allowlist.getProof(accounts.trustedProvider, capabilities.capMarketData);
  const makeValidReq = (nonceLabel, overrides = {}) => ({
    paymentNonce: keccak256(stringToHex(nonceLabel)),
    provider: accounts.trustedProvider,
    amount: 1_000_000n,
    resourceHash: keccak256(stringToHex(`/v1/${nonceLabel}`)),
    expectedPayloadHash: zeroHash,
    categoryHash: capabilities.capMarketData,
    merkleProof: validProof,
    forceEscrow: false,
    ...overrides,
  });

  const runViaEntryPoint = async (callData, signer = sessionKey, sigOverride = null, label = "atk") => {
    const hash = keccak256(stringToHex(`atk-${label}`));
    const signature = sigOverride ?? (await signer.sign({ hash }));
    return chain.writeContract({
      from: accounts.owner.address,
      to: entryPoint.address,
      abi: entryPoint.abi,
      functionName: "handleSingleOp",
      args: [makePackedUserOp({ sender: kernel.address, callData, signature }), hash],
    });
  };

  const baselineInner = buildSettleCallData(contracts.vault.abi, mandate, mandateSignature, "0x", makeValidReq("base"));
  const baselineCall = buildSingleExecCallData(kernel.abi, contracts.vault.address, 0n, baselineInner);

  // 1. Forged / attacker ECDSA signature -> AA24SignatureError
  await assert.rejects(() => runViaEntryPoint(baselineCall, accounts.attacker, null, "forged"), (e) => e.errorName === "AA24SignatureError");

  // 2. Truncated signature -> AA24SignatureError
  await assert.rejects(() => runViaEntryPoint(baselineCall, sessionKey, "0x1234", "short-sig"), (e) => e.errorName === "AA24SignatureError");

  // 3. Malleable high-s ECDSA signature (EIP-2 violation) -> AA24SignatureError
  const malHash = keccak256(stringToHex("atk-malleable"));
  const cleanSig = await sessionKey.sign({ hash: malHash });
  await assert.rejects(
    () => runViaEntryPoint(baselineCall, sessionKey, malleateSignature(cleanSig), "malleable"),
    (e) => e.errorName === "AA24SignatureError",
  );

  // 4. CALLTYPE_DELEGATECALL (0xff) smart-account takeover -> UnsupportedExecMode
  const delegateMode = `0xff${"00".repeat(31)}`;
  const delegateCall = buildSingleExecCallData(kernel.abi, contracts.vault.address, 0n, baselineInner, delegateMode);
  await assert.rejects(() => runViaEntryPoint(delegateCall, sessionKey, null, "delegatecall"), (e) => e.errorName === "UnsupportedExecMode");

  // 5. CALLTYPE_BATCH (0x01) smuggled second call -> UnsupportedExecMode
  const batchMode = `0x01${"00".repeat(31)}`;
  const batchCall = buildSingleExecCallData(kernel.abi, contracts.vault.address, 0n, baselineInner, batchMode);
  await assert.rejects(() => runViaEntryPoint(batchCall, sessionKey, null, "batch"), (e) => e.errorName === "UnsupportedExecMode");

  // 6. EXECTYPE_TRY (0x0001...) silent failure mode -> UnsupportedExecMode
  const tryMode = `0x0001${"00".repeat(30)}`;
  const tryCall = buildSingleExecCallData(kernel.abi, contracts.vault.address, 0n, baselineInner, tryMode);
  await assert.rejects(() => runViaEntryPoint(tryCall, sessionKey, null, "try-mode"), (e) => e.errorName === "UnsupportedExecMode");

  // 7. Non-execute outer selector (e.g., uninstallModule) -> DisallowedOuterSelector
  const uninstallCall = encodeFunctionData({
    abi: kernel.abi,
    functionName: "uninstallModule",
    args: [1n, validator.address, "0x"],
  });
  await assert.rejects(() => runViaEntryPoint(uninstallCall, sessionKey, null, "outer-sel"), (e) => e.errorName === "DisallowedOuterSelector");

  // 8. Malformed / truncated executionCalldata -> MalformedExecutionCalldata
  const malformedCall = concatHex(["0xe9ae5c53", zeroHash, padHex("0x40", { size: 32 }), padHex("0x10", { size: 32 }), "0x" + "aa".repeat(16)]);
  await assert.rejects(() => runViaEntryPoint(malformedCall, sessionKey, null, "malformed"), (e) => e.errorName === "MalformedExecutionCalldata");

  // 9. Non-zero native ETH value transfer -> NonZeroCallValue
  const ethDrainCall = buildSingleExecCallData(kernel.abi, contracts.vault.address, 1n, baselineInner);
  await assert.rejects(() => runViaEntryPoint(ethDrainCall, sessionKey, null, "eth-value"), (e) => e.errorName === "NonZeroCallValue");

  // 10. Arbitrary target bypass (direct USDC transfer instead of MandateVault) -> DisallowedTarget
  const directUsdcTransfer = encodeFunctionData({
    abi: contracts.usdc.abi,
    functionName: "transfer",
    args: [accounts.attacker.address, 10_000_000n],
  });
  const wrongTargetCall = buildSingleExecCallData(kernel.abi, contracts.usdc.address, 0n, directUsdcTransfer);
  await assert.rejects(() => runViaEntryPoint(wrongTargetCall, sessionKey, null, "wrong-target"), (e) => e.errorName === "DisallowedTarget");

  // 11. Privileged MandateVault admin functions -> DisallowedSelector
  const privilegedCalls = [
    encodeFunctionData({ abi: contracts.vault.abi, functionName: "withdrawPrincipal", args: [1_000_000n, accounts.attacker.address] }),
    encodeFunctionData({ abi: contracts.vault.abi, functionName: "harvestYield", args: [accounts.attacker.address] }),
    encodeFunctionData({ abi: contracts.vault.abi, functionName: "emergencyExitAave", args: [accounts.attacker.address] }),
    encodeFunctionData({ abi: contracts.vault.abi, functionName: "setPaused", args: [true] }),
    encodeFunctionData({ abi: contracts.vault.abi, functionName: "setDelegatedAuthorizer", args: [accounts.attacker.address, true] }),
  ];
  for (let i = 0; i < privilegedCalls.length; i++) {
    const privExec = buildSingleExecCallData(kernel.abi, contracts.vault.address, 0n, privilegedCalls[i]);
    await assert.rejects(() => runViaEntryPoint(privExec, sessionKey, null, `priv-${i}`), (e) => e.errorName === "DisallowedSelector");
  }

  // 12. Spoofed mandate.agent != smartAccount -> AgentAccountMismatch
  const wrongAgentMandate = { ...mandate, agent: accounts.attacker.address };
  const wrongAgentInner = buildSettleCallData(contracts.vault.abi, wrongAgentMandate, mandateSignature, "0x", makeValidReq("wrong-agent"));
  await assert.rejects(
    () => runViaEntryPoint(buildSingleExecCallData(kernel.abi, contracts.vault.address, 0n, wrongAgentInner), sessionKey, null, "wrong-agent"),
    (e) => e.errorName === "AgentAccountMismatch",
  );

  // 13. Unbound mandateId swap -> MandateIdMismatch
  const wrongIdMandate = { ...mandate, mandateId: keccak256(stringToHex("rogue-mandate-id")) };
  const wrongIdInner = buildSettleCallData(contracts.vault.abi, wrongIdMandate, mandateSignature, "0x", makeValidReq("wrong-id"));
  await assert.rejects(
    () => runViaEntryPoint(buildSingleExecCallData(kernel.abi, contracts.vault.address, 0n, wrongIdInner), sessionKey, null, "wrong-id"),
    (e) => e.errorName === "MandateIdMismatch",
  );

  // 14. Prompt-injected over-per-tx-cap (10.000001 USDC > 10.00 USDC) -> SessionPerTxCapExceeded
  const overCapInner = buildSettleCallData(contracts.vault.abi, mandate, mandateSignature, "0x", makeValidReq("over-cap", { amount: 10_000_001n }));
  await assert.rejects(
    () => runViaEntryPoint(buildSingleExecCallData(kernel.abi, contracts.vault.address, 0n, overCapInner), sessionKey, null, "over-cap"),
    (e) => e.errorName === "SessionPerTxCapExceeded",
  );

  // 15. Phishing / unallowlisted provider (bad Merkle proof) -> UnauthorizedProvider
  const phishInner = buildSettleCallData(contracts.vault.abi, mandate, mandateSignature, "0x", makeValidReq("phish", { provider: accounts.phishingAddress }));
  await assert.rejects(
    () => runViaEntryPoint(buildSingleExecCallData(kernel.abi, contracts.vault.address, 0n, phishInner), sessionKey, null, "phish"),
    (e) => e.errorName === "UnauthorizedProvider",
  );

  // 16. Low-reputation ERC-8004 provider (even if added to allowlist!) -> InsufficientProviderReputation
  const openSessionKey = privateKeyToAccount(generatePrivateKey());
  const regOpenData = encodeFunctionData({
    abi: validator.abi,
    functionName: "registerSessionKey",
    args: [{ ...defaultSessionConfig, sessionKey: openSessionKey.address, allowedProvidersRoot: zeroHash }],
  });
  await chain.writeContract({ from: accounts.owner.address, to: kernel.address, abi: kernel.abi, functionName: "executeOwnerCall", args: [validator.address, regOpenData] });
  const lowRepInner = buildSettleCallData(contracts.vault.abi, mandate, mandateSignature, "0x", makeValidReq("low-rep", { provider: accounts.lowRepProvider, merkleProof: [] }));
  await assert.rejects(
    () => runViaEntryPoint(buildSingleExecCallData(kernel.abi, contracts.vault.address, 0n, lowRepInner), openSessionKey, null, "low-rep"),
    (e) => e.errorName === "InsufficientProviderReputation",
  );

  // 17. Below anti-dust minimum settlement -> BelowMinimumSettlement
  const dustInner = buildSettleCallData(contracts.vault.abi, mandate, mandateSignature, "0x", makeValidReq("dust", { amount: 50n }));
  await assert.rejects(
    () => runViaEntryPoint(buildSingleExecCallData(kernel.abi, contracts.vault.address, 0n, dustInner), sessionKey, null, "dust"),
    (e) => e.errorName === "BelowMinimumSettlement",
  );

  // 18. Replay attack on already-settled paymentNonce -> PaymentNonceAlreadyUsed
  await runViaEntryPoint(baselineCall, sessionKey, null, "first-valid");
  await assert.rejects(
    () => runViaEntryPoint(baselineCall, sessionKey, null, "replay-same-nonce"),
    (e) => e.errorName === "PaymentNonceAlreadyUsed",
  );

  // 19. Revoked AP2 Mandate in MandateVault -> MandateAlreadyRevoked
  await chain.writeContract({ from: accounts.owner.address, to: contracts.vault.address, abi: contracts.vault.abi, functionName: "setMandateRevoked", args: [mandate.mandateId, true] });
  const postRevokeInner = buildSettleCallData(contracts.vault.abi, mandate, mandateSignature, "0x", makeValidReq("post-revoke"));
  await assert.rejects(
    () => runViaEntryPoint(buildSingleExecCallData(kernel.abi, contracts.vault.address, 0n, postRevokeInner), sessionKey, null, "post-revoke"),
    (e) => e.errorName === "MandateAlreadyRevoked",
  );
  await chain.writeContract({ from: accounts.owner.address, to: contracts.vault.address, abi: contracts.vault.abi, functionName: "setMandateRevoked", args: [mandate.mandateId, false] });

  // 20. Vault paused -> VaultCurrentlyPaused
  await chain.writeContract({ from: accounts.owner.address, to: contracts.vault.address, abi: contracts.vault.abi, functionName: "setPaused", args: [true] });
  await assert.rejects(
    () => runViaEntryPoint(buildSingleExecCallData(kernel.abi, contracts.vault.address, 0n, postRevokeInner), sessionKey, null, "paused"),
    (e) => e.errorName === "VaultCurrentlyPaused",
  );
  await chain.writeContract({ from: accounts.owner.address, to: contracts.vault.address, abi: contracts.vault.abi, functionName: "setPaused", args: [false] });

  // 21. Spoofed direct caller (msg.sender != userOp.sender) -> SmartAccountMismatch
  const directHash = keccak256(stringToHex("direct-spoof"));
  const directSig = await sessionKey.sign({ hash: directHash });
  await assert.rejects(
    () => chain.readContract({
      from: accounts.attacker.address,
      to: validator.address,
      abi: validator.abi,
      functionName: "validateUserOp",
      args: [makePackedUserOp({ sender: kernel.address, callData: buildSingleExecCallData(kernel.abi, contracts.vault.address, 0n, postRevokeInner), signature: directSig }), directHash],
    }),
    (e) => e.message.includes("SmartAccountMismatch"),
  );

  // 22. Yield-theft / principal exhaustion guard + Expired session enforcement via EntryPoint
  // Withdraw 48.5 USDC principal leaving only 0.5 USDC principal while Aave yield accrues
  chain.advanceTime(365 * 86_400);
  await chain.writeContract({ from: accounts.owner.address, to: contracts.vault.address, abi: contracts.vault.abi, functionName: "withdrawPrincipal", args: [48_500_000n, accounts.owner.address] });
  const yieldTheftInner = buildSettleCallData(contracts.vault.abi, mandate, mandateSignature, "0x", makeValidReq("yield-theft", { amount: 1_000_000n }));
  await assert.rejects(
    () => runViaEntryPoint(buildSingleExecCallData(kernel.abi, contracts.vault.address, 0n, yieldTheftInner), sessionKey, null, "yield-theft"),
    (e) => e.errorName === "InsufficientVaultPrincipal",
  );

  // Advance past session.validUntil (1,890,000,000) -> EntryPoint enforces AA22ExpiredOrNotDue via packed ValidationData
  chain.setTimestamp(1_895_000_000n);
  const expiredInner = buildSettleCallData(contracts.vault.abi, mandate, mandateSignature, "0x", makeValidReq("expired-session", { amount: 250_000n }));
  await assert.rejects(
    () => runViaEntryPoint(buildSingleExecCallData(kernel.abi, contracts.vault.address, 0n, expiredInner), sessionKey, null, "expired-session"),
    (e) => e.errorName === "AA22ExpiredOrNotDue",
  );
});

test("5. Full Trifecta Flow: ZeroDev Kernel v3.1 (ERC-7579) + Rust Stylus Ed25519 Coprocessor + Arbitrum Aave V3 x402", async () => {
  const ctx = await deployZeroDevFixture({ initialPrincipalUsdc: 1_000_000_000n, enableStylusPrecompile: true });
  const { chain, accounts, capabilities, contracts, entryPoint, validator, kernel, allowlist, defaultSessionConfig, sessionKey } = ctx;

  // 1. Approve Rust Arbitrum Stylus Ed25519 Coprocessor (0x000...579105) on MandateVault
  await chain.writeContract({
    from: accounts.owner.address,
    to: contracts.vault.address,
    abi: contracts.vault.abi,
    functionName: "setVerifierApproval",
    args: [STYLUS_COPROCESSOR_ADDRESS, true],
  });

  // 2. Build Stylus-verified AP2 Mandate targeting the ZeroDev Kernel Smart Account as `agent`
  const stylusMandateId = keccak256(stringToHex("trifecta-zerodev-stylus-aave-v1"));
  const stylusMandate = {
    mandateId: stylusMandateId,
    agent: kernel.address,
    maxPerTx: 10_000_000n,
    maxRolling24h: 50_000_000n,
    validAfter: 1_760_000_000n,
    deadline: 1_900_000_000n,
    minProviderReputationBps: 8_000,
    allowedProvidersRoot: allowlist.root,
    escrowThreshold: 5_000_000n,
    disputeWindowSeconds: 1_800n,
    verifierOverride: STYLUS_COPROCESSOR_ADDRESS,
  };

  const onChainDigest = await chain.readContract({
    to: contracts.vault.address,
    abi: contracts.vault.abi,
    functionName: "computeMandateDigest",
    args: [stylusMandate],
  });

  // Sign mandate digest using compiled Rust Stylus RFC 8032 Ed25519 binary
  const seedHex = "0x9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
  const edSigned = signStylusEd25519Mandate(seedHex, onChainDigest);
  await chain.writeContract({
    from: accounts.owner.address,
    to: contracts.vault.address,
    abi: contracts.vault.abi,
    functionName: "setDelegatedAuthorizer",
    args: [edSigned.authorizer, true],
  });

  // 3. Install ZeroDevMandateValidator onto Kernel Smart Account bound to `stylusMandateId`
  await chain.writeContract({
    from: accounts.owner.address,
    to: kernel.address,
    abi: kernel.abi,
    functionName: "installModule",
    args: [1n, validator.address, encodeSessionInit({ ...defaultSessionConfig, boundMandateId: stylusMandateId })],
  });

  // Advance 14 days so Aave V3 accrues real interest
  chain.advanceTime(14 * 86_400);

  // 4. Execute x402 payment through ALL THREE tracks in a single EntryPoint UserOp!
  const proof = allowlist.getProof(accounts.trustedProvider, capabilities.capMarketData);
  const settleInner = buildSettleCallData(
    contracts.vault.abi,
    stylusMandate,
    edSigned.signature,
    edSigned.pubkey,
    {
      paymentNonce: keccak256(stringToHex("trifecta-payment-001")),
      provider: accounts.trustedProvider,
      amount: 1_250_000n, // 1.25 USDC
      resourceHash: keccak256(stringToHex("/v1/trifecta-ai-inference")),
      expectedPayloadHash: zeroHash,
      categoryHash: capabilities.capMarketData,
      merkleProof: proof,
      forceEscrow: false,
    },
  );
  const opCallData = buildSingleExecCallData(kernel.abi, contracts.vault.address, 0n, settleInner);
  const opHash = keccak256(stringToHex("trifecta-userop-001"));
  const sessionSig = await sessionKey.sign({ hash: opHash });

  await chain.writeContract({
    from: accounts.owner.address,
    to: entryPoint.address,
    abi: entryPoint.abi,
    functionName: "handleSingleOp",
    args: [makePackedUserOp({ sender: kernel.address, callData: opCallData, signature: sessionSig, nonce: 1n }), opHash],
  });

  // Verify ALL THREE track outputs simultaneously!
  assert.equal(
    await chain.readContract({ to: contracts.usdc.address, abi: contracts.usdc.abi, functionName: "balanceOf", args: [accounts.trustedProvider] }),
    1_250_000n,
    "Provider paid 1.25 USDC via ZeroDev Kernel UserOp + Rust Stylus Ed25519 + Aave V3 atomic withdraw",
  );
  const metrics = await chain.readContract({ to: contracts.vault.address, abi: contracts.vault.abi, functionName: "vaultYieldMetrics" });
  assert.equal(metrics[1], 998_750_000n, "Principal decreased by exact 1.25 USDC");
  assert.ok(metrics[2] >= 1_100_000n, `Owner retains 100% of accrued 14-day Aave V3 interest (${metrics[2]})`);
  const provId = await chain.readContract({ to: contracts.registry.address, abi: contracts.registry.abi, functionName: "getAgentIdentity", args: [accounts.trustedProvider] });
  assert.equal(Number(provId.reputationBps), 9_225, "ERC-8004 reputation incremented +25 bps");

  console.log(
    `[zerodev-trifecta] PASS: Kernel v3.1 ERC-7579 -> ZeroDevMandateValidator -> Stylus Rust Ed25519 (0x...579105) -> Aave V3 (principal=${metrics[1]}, ownerYield=${metrics[2]}, rep=${provId.reputationBps} bps)`,
  );
});
