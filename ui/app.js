const ARBITRUM_ONE_RPC = "https://arb1.arbitrum.io/rpc";
const ARBITRUM_ONE_USDC = "0xaf88d065e77c8cC2239327C5EDb3A432268e5831";
const ARBITRUM_ONE_AAVE_V3_POOL = "0x794a61358D6845594F94dc1DB02A252b5b4814aD";
const ARBITRUM_ONE_AARB_USDCN = "0x724dc807b04555b71ed48a6896b6F41593b8C637";

const state = {
  principalUsdc: 1000.0,
  ownerYieldUsdc: 2.500521,
  escrowLockedUsdc: 0.0,
  rollingSpendUsdc: 0.0,
  rollingTxCount: 0,
  maxPerTxUsdc: 10.0,
  maxRolling24hUsdc: 50.0,
  minRepBps: 8000,
  escrowThresholdUsdc: 5.0,
  verifierTrack: "eip712",
  liveAprPercent: 3.0423,
  liveBlockNumber: 0,
};

function el(id) {
  return document.getElementById(id);
}

function formatNumber(n, decimals = 2) {
  return Number(n).toLocaleString("en-US", {
    minimumFractionDigits: decimals,
    maximumFractionDigits: decimals,
  });
}

function switchTab(tabName) {
  for (const btn of document.querySelectorAll(".tab-btn")) {
    btn.classList.toggle("active", btn.dataset.tab === tabName);
  }
  for (const sec of document.querySelectorAll(".view-section")) {
    sec.classList.toggle("active", sec.id === `view-${tabName}`);
  }
}

async function sha256HexBrowser(input) {
  const bytes = new TextEncoder().encode(input);
  const hashBuf = await crypto.subtle.digest("SHA-256", bytes);
  return (
    "0x" +
    Array.from(new Uint8Array(hashBuf))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
  );
}

async function refreshMandateDigest() {
  const payload = JSON.stringify({
    chainId: 42161,
    name: "MandateVault",
    version: "1",
    maxPerTx: Math.round(state.maxPerTxUsdc * 1e6),
    maxRolling24h: Math.round(state.maxRolling24hUsdc * 1e6),
    minProviderReputationBps: state.minRepBps,
    escrowThreshold: Math.round(state.escrowThresholdUsdc * 1e6),
    verifierTrack: state.verifierTrack,
  });
  const digest = await sha256HexBrowser(payload);
  const schemeLabel =
    state.verifierTrack === "stylus" ? "STYLUS-ED25519-AP2-V1" : "EIP712-SECP256K1-V1";
  el("mandateDigestBox").textContent = `[${schemeLabel}] Digest: ${digest.slice(0, 38)}...`;
}

function renderVaultMetrics() {
  el("vaultPrincipal").innerHTML = `${formatNumber(state.principalUsdc, 6)} <small>USDC</small>`;
  el("ownerYield").innerHTML = `+${formatNumber(state.ownerYieldUsdc, 6)} <small>aArbUSDCn</small>`;
  el("escrowLocked").innerHTML = `${formatNumber(state.escrowLockedUsdc, 6)} <small>USDC</small>`;
  el("rollingSpendVal").textContent = formatNumber(state.rollingSpendUsdc, 2);
  el("rollingCapVal").textContent = formatNumber(state.maxRolling24hUsdc, 2);
  el("activeWindowTxCount").textContent = `${state.rollingTxCount} active window tx(s)`;

  const pct = Math.min(100, (state.rollingSpendUsdc / Math.max(0.01, state.maxRolling24hUsdc)) * 100);
  const fill = el("rollingMeterFill");
  fill.style.width = `${pct.toFixed(1)}%`;
  fill.classList.toggle("danger", pct >= 85);
}

function renderTrace({ badgeText, badgeClass, headline, steps }) {
  const badge = el("traceStatusBadge");
  badge.className = `badge ${badgeClass}`;
  badge.textContent = badgeText;
  el("traceHeadline").textContent = headline;

  const list = el("atomicTraceList");
  list.innerHTML = "";
  for (const s of steps) {
    const li = document.createElement("li");
    li.className = `trace-step ${s.revert ? "step-revert" : "step-pass"}`;
    li.innerHTML = `
      <span class="step-tag">${s.tag}</span>
      <div>
        <strong>${s.title}</strong>
        <p>${s.detail}</p>
      </div>
    `;
    list.appendChild(li);
  }
}

async function loadBundledArbitrumSnapshot() {
  try {
    const resp = await fetch("./live_arbitrum_snapshot.json");
    if (!resp.ok) return;
    const snap = await resp.json();
    applyLiveTelemetry(snap, "Verified Snapshot");
  } catch {
    // Direct RPC query below populates live telemetry
  }
}

function applyLiveTelemetry(data, sourceTag) {
  state.liveBlockNumber = data.blockNumber;
  state.liveAprPercent = data.supplyAprPercent;
  el("liveBlockNumber").textContent = `#${Number(data.blockNumber).toLocaleString("en-US")}`;
  el("liveGasPrice").textContent = `${data.gasPriceGwei} gwei`;
  el("liveAaveApr").textContent = `${Number(data.supplyAprPercent).toFixed(4)}%`;
  el("livePoolTvl").innerHTML = `${formatNumber(data.aArbUsdcTotalSupplyUsdc, 0)} <small>USDC</small>`;
  el("snapshotTimestampBar").textContent =
    `${sourceTag} · Block #${data.blockNumber} · aArbUSDCn LiquidityIndex=${String(data.liquidityIndexRay).slice(0, 10)}...`;
}

async function syncLiveArbitrumRpc() {
  const btn = el("refreshRpcBtn");
  btn.textContent = "Querying arb1...";
  try {
    const paddedUsdc = ARBITRUM_ONE_USDC.slice(2).toLowerCase().padStart(64, "0");
    const paddedAToken = ARBITRUM_ONE_AARB_USDCN.slice(2).toLowerCase().padStart(64, "0");

    const batch = [
      { jsonrpc: "2.0", id: 1, method: "eth_blockNumber", params: [] },
      { jsonrpc: "2.0", id: 2, method: "eth_gasPrice", params: [] },
      {
        jsonrpc: "2.0",
        id: 3,
        method: "eth_call",
        params: [{ to: ARBITRUM_ONE_AAVE_V3_POOL, data: `0x35ea6a75${paddedUsdc}` }, "latest"],
      },
      {
        jsonrpc: "2.0",
        id: 4,
        method: "eth_call",
        params: [{ to: ARBITRUM_ONE_AARB_USDCN, data: "0x18160ddd" }, "latest"],
      },
      {
        jsonrpc: "2.0",
        id: 5,
        method: "eth_call",
        params: [{ to: ARBITRUM_ONE_USDC, data: `0x70a08231${paddedAToken}` }, "latest"],
      },
    ];

    const resp = await fetch(ARBITRUM_ONE_RPC, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(batch),
    });

    if (!resp.ok) {
      throw new Error(`HTTP ${resp.status}`);
    }

    const items = await resp.json();
    const map = new Map(items.map((i) => [i.id, i.result]));
    const blockNumber = Number(BigInt(map.get(1)));
    const gasPriceWei = BigInt(map.get(2));
    const rHex = map.get(3).slice(2);
    const liquidityIndex = BigInt("0x" + rHex.slice(64, 128));
    const currentLiquidityRate = BigInt("0x" + rHex.slice(128, 192));
    const totalSupplyRaw = BigInt(map.get(4));
    const cashRaw = BigInt(map.get(5));

    const aprPct = (Number(currentLiquidityRate) / 1e27) * 100;
    const liveData = {
      blockNumber,
      gasPriceGwei: (Number(gasPriceWei) / 1e9).toFixed(4),
      liquidityIndexRay: liquidityIndex.toString(),
      supplyAprPercent: Number(aprPct.toFixed(4)),
      aArbUsdcTotalSupplyUsdc: Number(totalSupplyRaw) / 1e6,
      poolAvailableCashUsdc: Number(cashRaw) / 1e6,
      fetchedAtIso: new Date().toISOString(),
    };

    applyLiveTelemetry(liveData, "LIVE RPC https://arb1.arbitrum.io/rpc");
    el("rpcStatusLabel").textContent = "LIVE RPC · arb1.arbitrum.io/rpc (CONNECTED)";
  } catch {
    el("rpcStatusLabel").textContent = "SNAPSHOT FALLBACK · arb1.arbitrum.io/rpc";
  } finally {
    btn.textContent = "Sync Live Arbitrum RPC";
  }
}

async function executeScenario(scenario) {
  for (const b of document.querySelectorAll(".scenario-btn")) {
    b.classList.toggle("active-scenario", b.dataset.scenario === scenario);
  }

  try {
    const apiResp = await fetch("/api/vault/simulate-action", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenario }),
    });
    if (apiResp.ok) {
      const data = await apiResp.json();
      if (data.telemetry) {
        state.principalUsdc = Number(data.telemetry.activePrincipalUsdc);
        state.ownerYieldUsdc = Number(data.telemetry.claimableOwnerYieldUsdc);
        state.escrowLockedUsdc = Number(data.telemetry.escrowedUsdc);
        state.rollingSpendUsdc = Number(data.telemetry.rolling24hSpendUsdc);
        state.rollingTxCount = Number(data.telemetry.rolling24hTxCount);
        renderVaultMetrics();
      }
    }
  } catch {
    applyDeterministicLocalState(scenario);
  }

  const verifierLabel =
    state.verifierTrack === "stylus"
      ? "StylusCoprocessor.verifyMandate (Ed25519 WASM · 0xf45d01ce)"
      : "Eip712MandateVerifier.verifyMandate (secp256k1 · 0xf45d01ce)";

  if (scenario === "normal_x402") {
    renderTrace({
      badgeText: "SETTLED · 200 OK",
      badgeClass: "badge-sage",
      headline: "Atomic 0.25 USDC x402 Redemption Settled (~158,400 gas · <$0.0002 on Arb1)",
      steps: [
        { tag: "HTTP 402", title: "GET /api/x402/market-feed -> 402 Payment Required", detail: "Challenge nonce issued for 250,000 micro-USDC (0.25 USDC)" },
        { tag: "VERIFY", title: verifierLabel, detail: "Valid owner signature recovered; non-malleable digest matched" },
        { tag: "ERC-8004", title: "ERC8004AgentRegistry.checkProviderEligibility()", detail: "Provider 0x1111...8004 score 9,200 bps >= Mandate min 8,000 bps" },
        { tag: "AAVE V3", title: "IAaveV3Pool.withdraw(USDC, 250000, provider)", detail: "Exact 0.25 USDC principal redeemed; 100% accrued aArbUSDCn yield retained for Owner" },
        { tag: "UNLOCK", title: "Retry with X-Payment-Proof -> 200 OK", detail: "Provider reputation incremented +25 bps to 9,225 bps" },
      ],
    });
  } else if (scenario === "prompt_injection_overcap") {
    renderTrace({
      badgeText: "REVERTED · 0 LOSS",
      badgeClass: "badge-crimson",
      headline: "Blocked: PerTxCapExceeded(500000000, " + Math.round(state.maxPerTxUsdc * 1e6) + ")",
      steps: [
        { tag: "INJECT", title: "Adversarial Prompt Override Attempted", detail: "Agent tricked into requesting 500.00 USDC drain to external endpoint" },
        { tag: "VERIFY", title: verifierLabel, detail: "Human AP2 Mandate cryptographically locks maxPerTx = " + state.maxPerTxUsdc.toFixed(2) + " USDC" },
        { tag: "REVERT", title: "MandateVault.settleX402Payment -> HARD REVERT", detail: "Custom Error PerTxCapExceeded: 0.000000 USDC transferred; Aave V3 principal untouched", revert: true },
      ],
    });
  } else if (scenario === "sybil_split_24h") {
    renderTrace({
      badgeText: "REVERTED · SYBIL",
      badgeClass: "badge-crimson",
      headline: "Blocked: Rolling24hWindowCapExceeded(57000000, " + Math.round(state.maxRolling24hUsdc * 1e6) + ")",
      steps: [
        { tag: "SPLIT 1-5", title: "5 × 9.50 USDC Sub-Cap Micro-Orders inside 86,400s Window", detail: "Cumulative sliding window spend reaches 47.50 / " + state.maxRolling24hUsdc.toFixed(2) + " USDC" },
        { tag: "SPLIT #6", title: "6th Split Order (+9.50 USDC -> 57.00 USDC projected)", detail: "MandateVault._recordRollingSpend prunes 0 expired slots (< 86,400s elapsed)" },
        { tag: "REVERT", title: "Rolling24hWindowCapExceeded Deterministic Rollback", detail: "Sybil split-order bypass defeated mathematically on-chain", revert: true },
      ],
    });
  } else {
    renderTrace({
      badgeText: "REFUNDED TO AAVE",
      badgeClass: "badge-gold",
      headline: "Escrow Frozen on SHA-256 Mismatch -> 6.00 USDC Re-Supplied to Aave V3",
      steps: [
        { tag: "ESCROW", title: "Order 6.00 USDC >= 5.00 USDC Threshold -> EscrowStatus.Locked", detail: "Principal held in MandateVault timelock escrow with expectedPayloadHash commitment" },
        { tag: "SHA-256", title: "Agent SDK Detects Corrupted Payload Delivery", detail: "Observed SHA-256 != expectedPayloadHash -> MandateVault.raiseDispute() freezes release" },
        { tag: "REFUND", title: "MandateVault.resolveDispute(escrowId, true)", detail: "6.00 USDC re-supplied directly into Aave V3 aArbUSDCn; malicious provider slashed -1,500 bps" },
      ],
    });
  }
}

function applyDeterministicLocalState(scenario) {
  state.ownerYieldUsdc += 0.000412;
  if (scenario === "normal_x402") {
    if (state.rollingSpendUsdc + 0.25 <= state.maxRolling24hUsdc && state.principalUsdc >= 0.25) {
      state.principalUsdc -= 0.25;
      state.rollingSpendUsdc += 0.25;
      state.rollingTxCount += 1;
    }
  } else if (scenario === "sybil_split_24h") {
    while (state.rollingSpendUsdc + 9.5 <= state.maxRolling24hUsdc && state.principalUsdc >= 9.5) {
      state.principalUsdc -= 9.5;
      state.rollingSpendUsdc += 9.5;
      state.rollingTxCount += 1;
    }
  }
  renderVaultMetrics();
}

// Event Wiring
for (const btn of document.querySelectorAll(".tab-btn")) {
  btn.addEventListener("click", () => switchTab(btn.dataset.tab));
}

el("refreshRpcBtn").addEventListener("click", () => {
  syncLiveArbitrumRpc();
});

el("mandateForm").addEventListener("submit", (ev) => {
  ev.preventDefault();
  state.maxPerTxUsdc = Number(el("inputMaxPerTx").value) || 10;
  state.maxRolling24hUsdc = Number(el("inputMax24h").value) || 50;
  state.minRepBps = Number(el("inputMinRep").value) || 8000;
  state.escrowThresholdUsdc = Number(el("inputEscrowThreshold").value) || 5;
  state.verifierTrack = el("selectVerifier").value;
  renderVaultMetrics();
  refreshMandateDigest();
});

for (const btn of document.querySelectorAll(".scenario-btn")) {
  btn.addEventListener("click", () => {
    executeScenario(btn.dataset.scenario);
  });
}

// Support URL `?tab=` deep-linking
const urlTab = new URLSearchParams(window.location.search).get("tab");
if (urlTab && ["vault", "stylus", "proof", "sdk"].includes(urlTab)) {
  switchTab(urlTab);
}

renderVaultMetrics();
refreshMandateDigest();
await loadBundledArbitrumSnapshot();
await syncLiveArbitrumRpc();
