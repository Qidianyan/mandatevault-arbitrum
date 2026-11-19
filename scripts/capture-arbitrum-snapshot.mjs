import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { fetchArbitrumOneLiveTelemetry } from "../sdk/typescript/index.ts";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const UI_DIR = path.resolve(__dirname, "..", "ui");
const OUT_FILE = path.join(UI_DIR, "live_arbitrum_snapshot.json");

async function main() {
  fs.mkdirSync(UI_DIR, { recursive: true });
  const snapshot = await fetchArbitrumOneLiveTelemetry("https://arb1.arbitrum.io/rpc");
  fs.writeFileSync(OUT_FILE, JSON.stringify(snapshot, null, 2));
  console.log(
    `[snapshot] Captured live Arbitrum One RPC snapshot @ block #${snapshot.blockNumber} | APR=${snapshot.supplyAprPercent}% | APY=${snapshot.supplyApyPercent}% | aArbUSDCn TVL=$${snapshot.aArbUsdcTotalSupplyUsdc.toLocaleString()}`,
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
