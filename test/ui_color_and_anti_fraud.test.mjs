import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CODE_ROOT = path.resolve(__dirname, "..");
const PROJECT_ROOT = path.basename(CODE_ROOT) === "code" ? path.resolve(CODE_ROOT, "..") : CODE_ROOT;
const UI_DIR = path.join(CODE_ROOT, "ui");

function rgbToHsl(r, g, b) {
  const rn = r / 255;
  const gn = g / 255;
  const bn = b / 255;
  const max = Math.max(rn, gn, bn);
  const min = Math.min(rn, gn, bn);
  const l = (max + min) / 2;
  if (max === min) {
    return { h: 0, s: 0, l: l * 100 };
  }
  const d = max - min;
  const s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
  let h = 0;
  if (max === rn) {
    h = (gn - bn) / d + (gn < bn ? 6 : 0);
  } else if (max === gn) {
    h = (bn - rn) / d + 2;
  } else {
    h = (rn - gn) / d + 4;
  }
  return { h: h * 60, s: s * 100, l: l * 100 };
}

function parseHexColor(hex) {
  const raw = hex.slice(1);
  if (raw.length === 3) {
    return {
      r: parseInt(raw[0] + raw[0], 16),
      g: parseInt(raw[1] + raw[1], 16),
      b: parseInt(raw[2] + raw[2], 16),
    };
  }
  if (raw.length === 6 || raw.length === 8) {
    return {
      r: parseInt(raw.slice(0, 2), 16),
      g: parseInt(raw.slice(2, 4), 16),
      b: parseInt(raw.slice(4, 6), 16),
    };
  }
  return null;
}

function collectFiles(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (
      entry.name === "node_modules" ||
      entry.name === "target" ||
      entry.name === "官方材料" ||
      entry.name === ".git"
    ) {
      continue;
    }
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      collectFiles(full, out);
    } else if (entry.isFile()) {
      out.push(full);
    }
  }
  return out;
}

test("1. Vault Terminal UI Zero-Forbidden-Color Audit (0 Blue, 0 Dark-Teal, 0 Cyan, 0 Purple) & Brand Palette Check", () => {
  const uiFiles = collectFiles(PROJECT_ROOT).filter((f) => /\.(html|css|svg)$/i.test(f) || (f.startsWith(UI_DIR) && f.endsWith(".js")));
  assert.ok(uiFiles.length >= 3, "Expected index.html, styles.css, app.js in code/ui/");
  const demoVideoPath = path.join(PROJECT_ROOT, "materials", "video", "MandateVault_Arbitrum_S+_Demo.mp4");
  if (fs.existsSync(demoVideoPath)) {
    assert.ok(fs.statSync(demoVideoPath).size > 1_000_000, "Demo MP4 must be a valid >1MB rendered video");
  }

  const forbiddenNamedColors = /\b(blue|cyan|teal|aqua|aquamarine|turquoise|purple|violet|indigo|magenta|slateblue|royalblue|navy|dodgerblue|deepskyblue|cornflowerblue)\b/i;
  const forbiddenTailwind = /\b(bg|text|border|from|via|to|ring)-(blue|sky|cyan|teal|indigo|violet|purple|fuchsia)-\d+\b/i;

  const violations = [];
  let sawObsidian121210 = false;
  let sawWarmGoldD97706 = false;
  let sawLiveArbRpc = false;

  for (const filePath of uiFiles) {
    const content = fs.readFileSync(filePath, "utf8");
    const rel = path.relative(PROJECT_ROOT, filePath);

    if (content.toLowerCase().includes("#121210")) sawObsidian121210 = true;
    if (content.toLowerCase().includes("#d97706")) sawWarmGoldD97706 = true;
    if (content.includes("https://arb1.arbitrum.io/rpc")) sawLiveArbRpc = true;

    if (forbiddenNamedColors.test(content)) {
      violations.push(`${rel}: matched forbidden CSS color keyword`);
    }
    if (forbiddenTailwind.test(content)) {
      violations.push(`${rel}: matched forbidden Tailwind blue/cyan/teal/purple utility`);
    }

    // Scan every #HEX color literal (skip 0x... Ethereum addresses)
    const hexRegex = /(?<![0-9a-zA-Z])#([0-9a-fA-F]{3}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})\b/g;
    for (const match of content.matchAll(hexRegex)) {
      const rgb = parseHexColor(match[0]);
      if (!rgb) continue;
      const { h, s } = rgbToHsl(rgb.r, rgb.g, rgb.b);
      // Hue 160°..325° covers all dark-teal, cyan, sky, blue, indigo, violet, purple, magenta
      if (s > 10 && h >= 160 && h <= 325) {
        violations.push(`${rel}: forbidden cool/purple hex ${match[0]} (hue=${h.toFixed(1)}°, sat=${s.toFixed(1)}%)`);
      }
    }

    // Scan rgb(...) / rgba(...) literals
    const rgbRegex = /rgba?\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})/gi;
    for (const match of content.matchAll(rgbRegex)) {
      const { h, s } = rgbToHsl(Number(match[1]), Number(match[2]), Number(match[3]));
      if (s > 10 && h >= 160 && h <= 325) {
        violations.push(`${rel}: forbidden rgb() color ${match[0]} (hue=${h.toFixed(1)}°)`);
      }
    }
  }

  assert.deepEqual(violations, [], `UI Color Gate Violations:\n${violations.join("\n")}`);
  assert.equal(sawObsidian121210, true, "Vault Terminal must feature Deep Obsidian #121210");
  assert.equal(sawWarmGoldD97706, true, "Vault Terminal must feature Warm Crimson-Gold #D97706");
  assert.equal(sawLiveArbRpc, true, "Vault Terminal must connect to https://arb1.arbitrum.io/rpc");

  const snapPath = path.join(UI_DIR, "live_arbitrum_snapshot.json");
  assert.equal(fs.existsSync(snapPath), true, "Bundled live_arbitrum_snapshot.json must exist");
  const snap = JSON.parse(fs.readFileSync(snapPath, "utf8"));
  assert.equal(snap.chainId, 42161);
  assert.ok(snap.blockNumber > 400_000_000, "Snapshot must contain real Arbitrum One block height");
});

test("2. Zero-Placeholder & Anti-Secret-Leak Verification Across Codebase & Deliverables", () => {
  const allFiles = collectFiles(PROJECT_ROOT).filter((f) => {
    const base = path.basename(f);
    // Skip historical 01 research audit file which quotes HackQuest's raw webpage string and self-exclude this scanner file's regex literals
    if (base === "01_冠军级深度调研与方向校准报告.md") return false;
    if (path.resolve(f) === fileURLToPath(import.meta.url)) return false;
    if (f.includes(`${path.sep}artifacts${path.sep}`)) return false;
    if (base === "package-lock.json") return false;
    return /\.(sol|rs|ts|mjs|js|py|html|css|md|json|toml)$/i.test(f);
  });

  const bannedTokens = [
    "TO" + "DO",
    "FIX" + "ME",
    "[T" + "BD]",
    "【待" + "核实】",
    "【待 key " + "真跑】",
    "SIMULATED_" + "OK",
    "Not " + "implemented",
  ];

  const findings = [];
  for (const filePath of allFiles) {
    const text = fs.readFileSync(filePath, "utf8");
    const rel = path.relative(PROJECT_ROOT, filePath);
    for (const token of bannedTokens) {
      if (text.includes(token)) {
        findings.push(`${rel}: contains banned placeholder '${token}'`);
      }
    }
    // Check against hardcoded live private keys in env assignments
    if (/DEPLOYER_PRIVATE_KEY\s*=\s*["']?0x[0-9a-fA-F]{64}/.test(text)) {
      findings.push(`${rel}: contains hardcoded DEPLOYER_PRIVATE_KEY`);
    }
  }

  assert.deepEqual(findings, [], `Anti-Fraud Audit Findings:\n${findings.join("\n")}`);
});
