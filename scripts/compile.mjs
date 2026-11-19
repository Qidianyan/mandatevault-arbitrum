import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import solc from "solc";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(__dirname, "..");
const CONTRACTS_DIR = path.join(ROOT_DIR, "contracts");
const ARTIFACTS_DIR = path.join(ROOT_DIR, "artifacts");

function collectSoliditySources(dir, baseDir = dir, acc = {}) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      collectSoliditySources(fullPath, baseDir, acc);
    } else if (entry.isFile() && entry.name.endsWith(".sol")) {
      const relPath = path.relative(baseDir, fullPath).split(path.sep).join("/");
      acc[relPath] = { content: fs.readFileSync(fullPath, "utf8") };
    }
  }
  return acc;
}

export function compileContracts() {
  const sources = collectSoliditySources(CONTRACTS_DIR);
  const input = {
    language: "Solidity",
    sources,
    settings: {
      viaIR: true,
      optimizer: {
        enabled: true,
        runs: 200,
      },
      outputSelection: {
        "*": {
          "*": ["abi", "evm.bytecode.object", "evm.deployedBytecode.object", "evm.methodIdentifiers"],
        },
      },
    },
  };

  const output = JSON.parse(solc.compile(JSON.stringify(input)));

  if (output.errors) {
    const fatal = output.errors.filter((e) => e.severity === "error");
    for (const msg of output.errors) {
      const prefix = msg.severity === "error" ? "[SOLC ERROR]" : "[SOLC WARN]";
      console.log(`${prefix} ${msg.formattedMessage.trim()}`);
    }
    if (fatal.length > 0) {
      throw new Error(`Solidity compilation failed with ${fatal.length} error(s).`);
    }
  }

  fs.mkdirSync(ARTIFACTS_DIR, { recursive: true });
  const manifest = {
    compiler: solc.version(),
    compiledAt: new Date().toISOString(),
    contracts: {},
  };

  for (const [sourcePath, fileContracts] of Object.entries(output.contracts || {})) {
    for (const [contractName, data] of Object.entries(fileContracts)) {
      const bytecode = data.evm?.bytecode?.object || "";
      const deployedBytecode = data.evm?.deployedBytecode?.object || "";
      const artifact = {
        contractName,
        sourceName: sourcePath,
        abi: data.abi,
        bytecode: bytecode ? `0x${bytecode}` : "0x",
        deployedBytecode: deployedBytecode ? `0x${deployedBytecode}` : "0x",
        methodIdentifiers: data.evm?.methodIdentifiers || {},
        bytecodeBytes: bytecode.length / 2,
      };
      const outPath = path.join(ARTIFACTS_DIR, `${contractName}.json`);
      fs.writeFileSync(outPath, JSON.stringify(artifact, null, 2));
      manifest.contracts[contractName] = {
        sourceName: sourcePath,
        bytecodeBytes: artifact.bytecodeBytes,
        deployedBytes: deployedBytecode.length / 2,
      };
    }
  }

  fs.writeFileSync(path.join(ARTIFACTS_DIR, "manifest.json"), JSON.stringify(manifest, null, 2));
  return manifest;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const manifest = compileContracts();
  console.log(`[compile] Solidity ${manifest.compiler} compiled ${Object.keys(manifest.contracts).length} contracts/interfaces:`);
  for (const [name, info] of Object.entries(manifest.contracts)) {
    if (info.deployedBytes > 0) {
      console.log(`  - ${name.padEnd(26)} runtime=${String(info.deployedBytes).padStart(5)} B  init=${String(info.bytecodeBytes).padStart(5)} B  (${info.sourceName})`);
    }
  }
}
