import assert from "node:assert/strict";
import test from "node:test";
import { createAddressFromString } from "@ethereumjs/util";
import {
  bytesToHex,
  encodeFunctionData,
  hexToBytes,
  keccak256,
  stringToHex,
  zeroAddress,
  zeroHash,
} from "viem";
import {
  ARBITRUM_ONE_CHAIN_ID,
  buildProviderAllowlistMerkleTree,
  signAp2Mandate,
} from "../sdk/typescript/index.ts";
import { deployFullProtocolFixture } from "./evm_harness.mjs";

// Deterministic xorshift64* PRNG for reproducible 10,000-iteration EVM fuzzing
class DeterministicPrng {
  constructor(seed = 0x41524231_4f50454en) {
    this.state = BigInt.asUintN(64, seed === 0n ? 1n : seed);
  }

  nextU64() {
    let x = this.state;
    x ^= x >> 12n;
    x ^= BigInt.asUintN(64, x << 25n);
    x ^= x >> 27n;
    this.state = x;
    return BigInt.asUintN(64, x * 2685821657736338717n);
  }

  intBetween(minIncl, maxIncl) {
    const span = BigInt(maxIncl - minIncl + 1);
    return Number(BigInt(minIncl) + (this.nextU64() % span));
  }

  bigIntBetween(minIncl, maxIncl) {
    const span = maxIncl - minIncl + 1n;
    return minIncl + (this.nextU64() % span);
  }
}

function findUniqueMarkerOffset(haystack, needle) {
  let found = -1;
  outer: for (let i = 0; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    assert.equal(found, -1, "Sentinel marker must appear exactly once in ABI template");
    found = i;
  }
  assert.notEqual(found, -1, "Sentinel marker not found in ABI template");
  return found;
}

function writeUint256BE(buf, offset, value) {
  let v = value;
  for (let i = 31; i >= 0; i--) {
    buf[offset + i] = Number(v & 0xffn);
    v >>= 8n;
  }
}

function readUint256BE(buf) {
  if (!buf || buf.length < 32) return 0n;
  let v = 0n;
  for (let i = 0; i < 32; i++) {
    v = (v << 8n) | BigInt(buf[i]);
  }
  return v;
}

test("10,000-Run Randomized Parameter EVM Fuzz & Protocol Invariant Suite", async () => {
  const TOTAL_FUZZ_RUNS = 10_000;
  const prng = new DeterministicPrng(0x41524231_4f50454en);

  const initialDeposit = 50_000_000_000n; // 50,000.00 USDC initial principal in Aave V3
  const globalCap24h = 120_000_000n;      // 120.00 USDC vault-wide 24h rolling ceiling

  const fixture = await deployFullProtocolFixture({
    initialPrincipalUsdc: initialDeposit,
    globalMaxRolling24h: globalCap24h,
    enableStylusPrecompile: false,
  });

  const { chain, accounts, capabilities, contracts } = fixture;

  // Pre-fund callers once so direct EVM execution needs zero redundant state writes
  await chain.fundEth(accounts.agent.address);
  await chain.fundEth(accounts.attacker.address);
  await chain.fundEth(accounts.trustedProvider);

  const addrAgent = createAddressFromString(accounts.agent.address);
  const addrAttacker = createAddressFromString(accounts.attacker.address);
  const addrVault = createAddressFromString(contracts.vault.address);

  const bytesTrustedProvider = hexToBytes(accounts.trustedProvider);
  const bytesPhishingProvider = hexToBytes(accounts.phishingAddress);

  // Build O(1) Custom Error Selector Lookup Map from MandateVault ABI
  const errorSelectorMap = new Map();
  for (const item of contracts.vault.abi) {
    if (item.type === "error") {
      const inputsSig = (item.inputs || []).map((inp) => inp.type).join(",");
      const sel = keccak256(stringToHex(`${item.name}(${inputsSig})`)).slice(0, 10).toLowerCase();
      errorSelectorMap.set(sel, item.name);
    }
  }

  const allowlist = buildProviderAllowlistMerkleTree([
    { provider: accounts.trustedProvider, categoryHash: capabilities.capMarketData },
    { provider: accounts.trustedProvider, categoryHash: capabilities.capCompute },
    { provider: accounts.secondaryProvider, categoryHash: capabilities.capCompute },
  ]);
  const validMarketProof = allowlist.getProof(accounts.trustedProvider, capabilities.capMarketData);

  const sentinelNonce = "0xa1a2a3a4a5a6a7a8b1b2b3b4b5b6b7b8c1c2c3c4c5c6c7c8d1d2d3d4d5d6d7d8";
  const sentinelProvider = "0xdead0001dead0002dead0003dead0004dead0005";
  const sentinelAmount = 0x7172737475767778n;

  const mandateProfiles = [
    { id: "fuzz-m0", maxPerTx: 5_000_000n, max24h: 25_000_000n, minRep: 8_000, escrowAt: 4_000_000n },
    { id: "fuzz-m1", maxPerTx: 10_000_000n, max24h: 45_000_000n, minRep: 8_000, escrowAt: 8_000_000n },
    { id: "fuzz-m2", maxPerTx: 15_000_000n, max24h: 60_000_000n, minRep: 8_500, escrowAt: 10_000_000n },
    { id: "fuzz-m3", maxPerTx: 3_000_000n, max24h: 12_000_000n, minRep: 9_000, escrowAt: 2_500_000n },
    { id: "fuzz-m4", maxPerTx: 20_000_000n, max24h: 80_000_000n, minRep: 7_500, escrowAt: 15_000_000n },
    { id: "fuzz-m5", maxPerTx: 8_000_000n, max24h: 30_000_000n, minRep: 8_000, escrowAt: 6_000_000n },
  ];

  const signedMandates = [];
  for (const p of mandateProfiles) {
    const mandate = {
      mandateId: keccak256(stringToHex(p.id)),
      agent: accounts.agent.address,
      maxPerTx: p.maxPerTx,
      maxRolling24h: p.max24h,
      validAfter: 1_760_000_000n,
      deadline: 2_500_000_000n,
      minProviderReputationBps: p.minRep,
      allowedProvidersRoot: allowlist.root,
      escrowThreshold: p.escrowAt,
      disputeWindowSeconds: 1_200n,
      verifierOverride: zeroAddress,
    };
    const sig = await signAp2Mandate({
      ownerPrivateKey: accounts.ownerKey,
      chainId: ARBITRUM_ONE_CHAIN_ID,
      vaultAddress: contracts.vault.address,
      mandate,
    });
    const forgedSig = await signAp2Mandate({
      ownerPrivateKey: accounts.attackerKey,
      chainId: ARBITRUM_ONE_CHAIN_ID,
      vaultAddress: contracts.vault.address,
      mandate,
    });

    const buildTemplate = (sigHex) => {
      const encoded = hexToBytes(
        encodeFunctionData({
          abi: contracts.vault.abi,
          functionName: "settleX402Payment",
          args: [
            mandate,
            sigHex,
            "0x",
            {
              paymentNonce: sentinelNonce,
              provider: sentinelProvider,
              amount: sentinelAmount,
              resourceHash: keccak256(stringToHex("/fuzz/resource")),
              expectedPayloadHash: zeroHash,
              categoryHash: capabilities.capMarketData,
              merkleProof: validMarketProof,
              forceEscrow: false,
            },
          ],
        }),
      );
      const nonceOff = findUniqueMarkerOffset(encoded, hexToBytes(sentinelNonce));
      const providerOff = findUniqueMarkerOffset(
        encoded,
        hexToBytes(`0x000000000000000000000000${sentinelProvider.slice(2)}`),
      );
      const amountBytes = new Uint8Array(32);
      writeUint256BE(amountBytes, 0, sentinelAmount);
      const amountOff = findUniqueMarkerOffset(encoded, amountBytes);
      return { template: encoded, nonceOff, providerOff, amountOff };
    };

    const validTpl = buildTemplate(sig);
    const forgedTpl = buildTemplate(forgedSig);

    // Self-verify byte-exact equivalence between fast binary splice and full viem encodeFunctionData
    const testBuf = validTpl.template.slice();
    writeUint256BE(testBuf, validTpl.nonceOff, 42n);
    testBuf.fill(0, validTpl.providerOff, validTpl.providerOff + 12);
    testBuf.set(bytesTrustedProvider, validTpl.providerOff + 12);
    writeUint256BE(testBuf, validTpl.amountOff, 1_234_567n);
    const expectedHex = encodeFunctionData({
      abi: contracts.vault.abi,
      functionName: "settleX402Payment",
      args: [
        mandate,
        sig,
        "0x",
        {
          paymentNonce: `0x${(42n).toString(16).padStart(64, "0")}`,
          provider: accounts.trustedProvider,
          amount: 1_234_567n,
          resourceHash: keccak256(stringToHex("/fuzz/resource")),
          expectedPayloadHash: zeroHash,
          categoryHash: capabilities.capMarketData,
          merkleProof: validMarketProof,
          forceEscrow: false,
        },
      ],
    });
    assert.equal(bytesToHex(testBuf).toLowerCase(), expectedHex.toLowerCase());

    signedMandates.push({ mandate, validTpl, forgedTpl, windowEntries: [] });
  }

  // Reference Differential Oracle State
  const globalWindowEntries = [];
  const usedNonces = new Set();
  const activeEscrows = [];
  let modelPrincipal = initialDeposit;
  let modelSettled = 0n;
  let modelEscrowed = 0n;

  const stats = {
    settledDirect: 0,
    settledEscrow: 0,
    revertedOverPerTx: 0,
    revertedRolling24h: 0,
    revertedAuthOrSig: 0,
    revertedProviderOrRep: 0,
    revertedReplayOrDust: 0,
    escrowDisputeRefunds: 0,
    escrowTimelockReleases: 0,
  };

  function pruneReferenceWindow(entries, nowTs) {
    while (entries.length > 0 && entries[0].ts + 86_400n <= nowTs) {
      entries.shift();
    }
    let total = 0n;
    for (let i = 0; i < entries.length; i++) {
      total += entries[i].amount;
    }
    return total;
  }

  const startMs = performance.now();

  for (let iter = 0; iter < TOTAL_FUZZ_RUNS; iter++) {
    const dt = prng.intBetween(0, 4_500);
    if (dt > 0) {
      chain.timestamp += BigInt(dt);
    }
    chain.blockNumber += 1n;

    // Exercise Escrow Dispute Refunds & Timelock Releases periodically
    if (iter % 50 === 0 && activeEscrows.length > 0) {
      const targetIdx = prng.intBetween(0, activeEscrows.length - 1);
      const esc = activeEscrows[targetIdx];
      if (chain.timestamp < esc.unlockAt) {
        await chain.writeContract({
          from: accounts.agent.address,
          to: contracts.vault.address,
          abi: contracts.vault.abi,
          functionName: "raiseDispute",
          args: [esc.escrowId, keccak256(stringToHex(`bad-${iter}`)), "FUZZ_PAYLOAD_MISMATCH"],
        });
        await chain.writeContract({
          from: accounts.arbitrator.address,
          to: contracts.vault.address,
          abi: contracts.vault.abi,
          functionName: "resolveDispute",
          args: [esc.escrowId, true],
        });
        await chain.writeContract({
          from: accounts.owner.address,
          to: contracts.registry.address,
          abi: contracts.registry.abi,
          functionName: "setProviderReputation",
          args: [accounts.trustedProvider, 9_200],
        });
        modelEscrowed -= esc.amount;
        modelPrincipal += esc.amount;
        activeEscrows.splice(targetIdx, 1);
        stats.escrowDisputeRefunds++;
        continue;
      } else {
        await chain.writeContract({
          from: accounts.trustedProvider,
          to: contracts.vault.address,
          abi: contracts.vault.abi,
          functionName: "releaseEscrow",
          args: [esc.escrowId],
        });
        modelEscrowed -= esc.amount;
        modelSettled += esc.amount;
        activeEscrows.splice(targetIdx, 1);
        stats.escrowTimelockReleases++;
        continue;
      }
    }

    const slot = signedMandates[prng.intBetween(0, signedMandates.length - 1)];
    const { mandate } = slot;

    const roll = prng.intBetween(1, 100);
    let amount = prng.bigIntBetween(100n, mandate.maxPerTx + 8_000_000n);
    let useAttackerCaller = false;
    let useForgedSig = false;
    let usePhishingProvider = false;
    let nonceBig = BigInt(iter + 1) + 0x9000000000n;

    if (roll <= 6) {
      amount = prng.bigIntBetween(1n, 99n);
    } else if (roll <= 12 && usedNonces.size > 0) {
      nonceBig = usedNonces.values().next().value;
    } else if (roll <= 18) {
      useForgedSig = true;
    } else if (roll <= 23) {
      useAttackerCaller = true;
    } else if (roll <= 29) {
      usePhishingProvider = true;
    }

    const nowTs = chain.timestamp;
    const activeMandateSum = pruneReferenceWindow(slot.windowEntries, nowTs);
    const activeGlobalSum = pruneReferenceWindow(globalWindowEntries, nowTs);

    const shouldSucceed =
      !useAttackerCaller &&
      !useForgedSig &&
      !usedNonces.has(nonceBig) &&
      !usePhishingProvider &&
      amount >= 100n &&
      amount <= mandate.maxPerTx &&
      slot.windowEntries.length < 256 &&
      globalWindowEntries.length < 256 &&
      activeMandateSum + amount <= mandate.maxRolling24h &&
      activeGlobalSum + amount <= globalCap24h &&
      amount <= modelPrincipal;

    const tplObj = useForgedSig ? slot.forgedTpl : slot.validTpl;
    const calldata = tplObj.template.slice();
    writeUint256BE(calldata, tplObj.nonceOff, nonceBig);
    calldata.fill(0, tplObj.providerOff, tplObj.providerOff + 12);
    calldata.set(
      usePhishingProvider ? bytesPhishingProvider : bytesTrustedProvider,
      tplObj.providerOff + 12,
    );
    writeUint256BE(calldata, tplObj.amountOff, amount);

    const callerAddr = useAttackerCaller ? addrAttacker : addrAgent;
    const evmRes = await chain.evm.runCall({
      caller: callerAddr,
      origin: callerAddr,
      to: addrVault,
      data: calldata,
      gasLimit: 1_500_000n,
      block: chain.makeBlock(),
    });

    const succeeded = !evmRes.execResult.exceptionError;
    let revertName = null;
    if (!succeeded && evmRes.execResult.returnValue.length >= 4) {
      const sel4 = bytesToHex(evmRes.execResult.returnValue.subarray(0, 4)).toLowerCase();
      revertName = errorSelectorMap.get(sel4) ?? sel4;
    }

    assert.equal(
      succeeded,
      shouldSucceed,
      `Fuzz iter #${iter} divergence: EVM=${succeeded} (revert=${revertName}), oracle=${shouldSucceed}`,
    );

    if (succeeded) {
      usedNonces.add(nonceBig);
      slot.windowEntries.push({ ts: nowTs, amount });
      globalWindowEntries.push({ ts: nowTs, amount });
      modelPrincipal -= amount;

      const escrowId = readUint256BE(evmRes.execResult.returnValue);
      if (escrowId > 0n) {
        modelEscrowed += amount;
        activeEscrows.push({
          escrowId,
          amount,
          unlockAt: nowTs + mandate.disputeWindowSeconds,
        });
        stats.settledEscrow++;
      } else {
        modelSettled += amount;
        stats.settledDirect++;
      }
    } else {
      if (revertName === "PerTxCapExceeded") stats.revertedOverPerTx++;
      else if (
        revertName === "Rolling24hWindowCapExceeded" ||
        revertName === "RollingWindowTxCountExceeded"
      ) {
        stats.revertedRolling24h++;
      } else if (
        revertName === "InvalidMandateSignature" ||
        revertName === "CallerNotAuthorizedAgent"
      ) {
        stats.revertedAuthOrSig++;
      } else if (
        revertName === "UnauthorizedProvider" ||
        revertName === "InsufficientProviderReputation"
      ) {
        stats.revertedProviderOrRep++;
      } else {
        stats.revertedReplayOrDust++;
      }
    }

    // Deep On-Chain Solvency & Conservation Cross-Check Every 500 Iterations + Final Iteration
    if ((iter + 1) % 500 === 0 || iter === TOTAL_FUZZ_RUNS - 1) {
      const metrics = await chain.readContract({
        to: contracts.vault.address,
        abi: contracts.vault.abi,
        functionName: "vaultYieldMetrics",
      });
      const onChainATokenBal = metrics[0];
      const onChainPrincipal = metrics[1];
      const onChainOwnerYield = metrics[2];
      const onChainEscrowed = metrics[3];

      const onChainSettled = await chain.readContract({
        to: contracts.vault.address,
        abi: contracts.vault.abi,
        functionName: "totalSettledUsdc",
      });

      const onChainGlobalWin = await chain.readContract({
        to: contracts.vault.address,
        abi: contracts.vault.abi,
        functionName: "getGlobalRolling24hSpend",
      });
      const expectedGlobalWin = pruneReferenceWindow(globalWindowEntries, chain.timestamp);

      assert.equal(onChainPrincipal, modelPrincipal, `Principal mismatch at iter ${iter}`);
      assert.equal(onChainEscrowed, modelEscrowed, `Escrow mismatch at iter ${iter}`);
      assert.equal(onChainSettled, modelSettled, `Settled mismatch at iter ${iter}`);
      assert.equal(
        onChainPrincipal + onChainEscrowed + onChainSettled,
        initialDeposit,
        `Conservation law violated at iter ${iter}`,
      );
      assert.equal(onChainGlobalWin[0], expectedGlobalWin, `Global 24h window drift at iter ${iter}`);
      assert.ok(onChainGlobalWin[0] <= globalCap24h, "Global 24h cap breached");
      assert.ok(onChainATokenBal >= onChainPrincipal, "Aave V3 solvency invariant breached");
      assert.ok(onChainOwnerYield > 0n, "Accrued Aave V3 yield must remain ring-fenced for Vault Owner");
    }
  }

  const elapsedSec = ((performance.now() - startMs) / 1000).toFixed(2);
  console.log(
    `[fuzz] ${TOTAL_FUZZ_RUNS}/${TOTAL_FUZZ_RUNS} EVM fuzz runs PASSED in ${elapsedSec}s | Invariants=100% intact | Stats:`,
    stats,
  );
});
