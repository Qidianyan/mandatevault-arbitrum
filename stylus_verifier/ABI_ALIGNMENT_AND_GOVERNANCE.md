# Dual-Track Cryptographic Verifier Architecture: ABI Alignment & October 2026 Arbitrum Security Council Governance Response

## 1. Governance Context: Why Dual-Track (Mainnet Solidity + Sepolia Stylus Coprocessor)

On **October 2, 2026**, the **Arbitrum Security Council** executed an emergency parameter adjustment on **Arbitrum One (Chain ID `42161`)** and **Arbitrum Nova**, raising the WASM activation gas ceiling for *newly deployed* Arbitrum Stylus contracts to `2^64 - 1` (`18,446,744,073,709,551,615` gas). This temporary safeguard pauses new `cargo stylus activate` operations on mainnet while ArbOS WASM compilation defenses against adversarial machine-generated WASM payloads undergo hardening. Meanwhile:

1. **Arbitrum One EVM (`Solidity`)** deployments, Native USDC (`0xaf88d065e77c8cC2239327C5EDb3A432268e5831`), and Aave V3 Pool (`0x794a61358D6845594F94dc1DB02A252b5b4814aD`) operate at 100% normal throughput and sub-cent gas cost.
2. **Arbitrum Sepolia (`Chain ID 421614`)** and custom Arbitrum Orbit chains continue supporting Stylus WASM deployment and benchmarking.

If `MandateVault` coupled its core treasury custody directly into a monolithic Stylus WASM contract, mainnet deployment on Arbitrum One would be blocked at `ArbWasm.activateProgram`. Instead, `MandateVault` isolates signature verification behind the stateless `IMandateVerifier` interface:

```mermaid
flowchart LR
    Vault["MandateVault.sol (Arbitrum One Mainnet)"] -->|"mandate.verifierOverride == 0x0"| SolVerifier["Eip712MandateVerifier.sol (secp256k1 ECDSA)"]
    Vault -->|"mandate.verifierOverride == stylusAddr"| StylusVerifier["stylus_verifier (Rust WASM RFC 8032 Ed25519)"]
    Vault -->|"Atomic Supply / Withdraw"| Aave["Arbitrum One Aave V3 Pool (0x794a...14aD)"]
    Vault -->|"Reputation Check"| ERC8004["ERC8004AgentRegistry.sol"]
```

- **Day-1 Mainnet Production (`Arbitrum One`)**: `MandateVault.sol` settles live Native USDC via `Eip712MandateVerifier.sol` with zero dependency on WASM activation.
- **Arbitrum Sepolia & Post-Pause Mainnet (`Zero-Migration Upgrade`)**: Hardware enclave and WebAuthn/Passkey Ed25519 AP2 mandates route to `stylus_verifier`. The moment the Arbitrum Security Council restores normal WASM activation limits on Arbitrum One, the vault owner activates the Stylus coprocessor via a single transaction:
  ```solidity
  mandateVault.setVerifierApproval(stylusEd25519VerifierAddress, true);
  mandateVault.setDelegatedAuthorizer(derivedEd25519Authorizer, true);
  ```
  **Zero principal migration, zero Aave V3 withdrawal, and zero SDK breaking changes are required.**

---

## 2. Exact Binary ABI Alignment (`IMandateVerifier.sol` <-> `stylus_verifier/src/lib.rs`)

| Solidity Function Signature | 4-Byte Selector (`keccak256`) | Calldata Layout | Return Payload (`64` or `96` bytes) |
| :--- | :--- | :--- | :--- |
| `verifyMandate(bytes32,bytes,bytes)` | `keccak256("verifyMandate(bytes32,bytes,bytes)")[0..4]` | `[0..4]` selector<br>`[4..36]` `mandateDigest` (`bytes32`)<br>`[36..68]` offset to `signature` (`0x60`)<br>`[68..100]` offset to `verifierContext` (`0xc0`)<br>`[100..196]` length (`64`) + `R \|\| S` Ed25519 signature<br>`[196..260]` length (`32`) + 32-byte Ed25519 public key | `[0..32]` `bool valid` (`0x01` or `0x00`)<br>`[32..64]` `address authorizer` (`keccak256(pubkey32)[12..32]`) |
| `verifierScheme()` | `keccak256("verifierScheme()")[0..4]` | `[0..4]` selector | ABI-encoded `string` `"STYLUS-ED25519-AP2-V1"` |

### EIP-712 Struct Hash Parity (`MandateVault.hashMandate` == `stylus_verifier::hash_ap2_mandate`)

Both Solidity and Rust hash the identical 11-field AP2 `Mandate` type string:

```text
Mandate(bytes32 mandateId,address agent,uint256 maxPerTx,uint256 maxRolling24h,uint64 validAfter,uint64 deadline,uint16 minProviderReputationBps,bytes32 allowedProvidersRoot,uint256 escrowThreshold,uint64 disputeWindowSeconds,address verifierOverride)
```

### Cryptographic Hardening in `stylus_verifier`
- **Curve Arithmetic**: GF($2^{255}-19$) in $5 \times 51$-bit limbs (`u128` intermediates, zero overflow) with Hisil et al. (2008) extended twisted Edwards coordinates $(X:Y:Z:T)$.
- **Malleability Defense**: Strict canonical check $0 \le S < L$ ($L = 2^{252} + 27742317777372353535851937790883648493$) and canonical field encoding check $y < 2^{255}-19$ per IETF RFC 8032 §5.1.7.
- **Cofactored Equation**: Verifies $[8][S]B = [8]R + [8][k]A$ to prevent small-subgroup torsion attacks.
- **Gas Efficiency**: Pure Solidity Ed25519 field inversion and scalar multiplication consumes `~490,000–620,000` EVM gas (`ecrecover` precompile `0x01` only supports `secp256k1`). Compiled to Stylus WASM (`opt-level = "z"`, LTO, zero std bloat), Ed25519 verification executes in native WASM 64-bit integer instructions at an estimated **`~24,800` gas equivalent (~95% reduction)**.
