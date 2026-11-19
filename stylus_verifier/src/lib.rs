//! Arbitrum Stylus Pluggable Ed25519 + AP2 Mandate Coprocessor (`IMandateVerifier`)
//!
//! Targets Arbitrum Sepolia (`Chain ID 421614`) under MandateVault's Dual-Track Architecture:
//! - Track A (Arbitrum One Mainnet, Chain ID 42161): `Eip712MandateVerifier.sol` (secp256k1 ECDSA)
//! - Track B (Arbitrum Sepolia / Stylus Coprocessor): This WASM/Rust module verifying RFC 8032 Ed25519
//!   passkey/enclave AP2 Mandates through the exact Solidity `IMandateVerifier` ABI:
//!   `verifyMandate(bytes32 mandateDigest, bytes signature, bytes verifierContext) -> (bool valid, address authorizer)`
//!   `verifierScheme() -> string`

pub mod ed25519;
pub mod keccak;

use ed25519::{ed25519_public_key, ed25519_sign, ed25519_verify};
use keccak::keccak256;

/// Canonical scheme tag returned by `IMandateVerifier.verifierScheme()`.
pub const VERIFIER_SCHEME: &str = "STYLUS-ED25519-AP2-V1";

/// Computes the 4-byte Solidity function selector for a signature string.
pub fn selector(sig: &str) -> [u8; 4] {
    let hash = keccak256(sig.as_bytes());
    [hash[0], hash[1], hash[2], hash[3]]
}

/// Deterministically maps a 32-byte Ed25519 public key into a 20-byte EVM authorizer identity
/// (`address(uint160(uint256(keccak256(pubkey32))))`), registered on `MandateVault` via `setDelegatedAuthorizer`.
pub fn derive_authorizer_address(ed25519_pubkey: &[u8; 32]) -> [u8; 20] {
    let digest = keccak256(ed25519_pubkey);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&digest[12..32]);
    addr
}

/// AP2 Mandate Parameters matching `MandateVault.Mandate` in Solidity 1:1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ap2Mandate {
    pub mandate_id: [u8; 32],
    pub agent: [u8; 20],
    pub max_per_tx: u128,
    pub max_rolling_24h: u128,
    pub valid_after: u64,
    pub deadline: u64,
    pub min_provider_reputation_bps: u16,
    pub allowed_providers_root: [u8; 32],
    pub escrow_threshold: u128,
    pub dispute_window_seconds: u64,
    pub verifier_override: [u8; 20],
}

/// Computes the exact EIP-712 `hashMandate(Mandate)` struct hash matching `MandateVault.sol`.
pub fn hash_ap2_mandate(m: &Ap2Mandate) -> [u8; 32] {
    let typehash = keccak256(
        b"Mandate(bytes32 mandateId,address agent,uint256 maxPerTx,uint256 maxRolling24h,uint64 validAfter,uint64 deadline,uint16 minProviderReputationBps,bytes32 allowedProvidersRoot,uint256 escrowThreshold,uint64 disputeWindowSeconds,address verifierOverride)",
    );

    let mut encoded = Vec::with_capacity(12 * 32);
    encoded.extend_from_slice(&typehash);
    encoded.extend_from_slice(&m.mandate_id);
    encoded.extend_from_slice(&pad_address(&m.agent));
    encoded.extend_from_slice(&pad_u128(m.max_per_tx));
    encoded.extend_from_slice(&pad_u128(m.max_rolling_24h));
    encoded.extend_from_slice(&pad_u64(m.valid_after));
    encoded.extend_from_slice(&pad_u64(m.deadline));
    encoded.extend_from_slice(&pad_u64(m.min_provider_reputation_bps as u64));
    encoded.extend_from_slice(&m.allowed_providers_root);
    encoded.extend_from_slice(&pad_u128(m.escrow_threshold));
    encoded.extend_from_slice(&pad_u64(m.dispute_window_seconds));
    encoded.extend_from_slice(&pad_address(&m.verifier_override));

    keccak256(&encoded)
}

/// Computes the exact EIP-712 digest `\x19\x01 || domainSeparator || hashMandate(m)` matching `MandateVault.sol`.
pub fn compute_eip712_mandate_digest(chain_id: u64, verifying_vault: &[u8; 20], m: &Ap2Mandate) -> [u8; 32] {
    let domain_typehash =
        keccak256(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    let name_hash = keccak256(b"MandateVault");
    let version_hash = keccak256(b"1");

    let mut dom_buf = Vec::with_capacity(5 * 32);
    dom_buf.extend_from_slice(&domain_typehash);
    dom_buf.extend_from_slice(&name_hash);
    dom_buf.extend_from_slice(&version_hash);
    dom_buf.extend_from_slice(&pad_u64(chain_id));
    dom_buf.extend_from_slice(&pad_address(verifying_vault));
    let domain_separator = keccak256(&dom_buf);

    let struct_hash = hash_ap2_mandate(m);
    let mut msg = [0u8; 66];
    msg[0] = 0x19;
    msg[1] = 0x01;
    msg[2..34].copy_from_slice(&domain_separator);
    msg[34..66].copy_from_slice(&struct_hash);
    keccak256(&msg)
}

fn pad_address(addr: &[u8; 20]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..32].copy_from_slice(addr);
    out
}

fn pad_u64(v: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&v.to_be_bytes());
    out
}

fn pad_u128(v: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..32].copy_from_slice(&v.to_be_bytes());
    out
}

fn read_u256_usize(word: &[u8]) -> Option<usize> {
    if word.len() != 32 {
        return None;
    }
    if word[..24].iter().any(|&b| b != 0) {
        return None;
    }
    let mut low = [0u8; 8];
    low.copy_from_slice(&word[24..32]);
    Some(u64::from_be_bytes(low) as usize)
}

fn decode_abi_bytes<'a>(args: &'a [u8], head_offset: usize) -> Option<&'a [u8]> {
    if head_offset + 32 > args.len() {
        return None;
    }
    let dyn_offset = read_u256_usize(&args[head_offset..head_offset + 32])?;
    if dyn_offset + 32 > args.len() {
        return None;
    }
    let len = read_u256_usize(&args[dyn_offset..dyn_offset + 32])?;
    let start = dyn_offset.checked_add(32)?;
    let end = start.checked_add(len)?;
    if end > args.len() {
        return None;
    }
    Some(&args[start..end])
}

fn encode_verify_response(valid: bool, authorizer: &[u8; 20]) -> Vec<u8> {
    let mut out = vec![0u8; 64];
    if valid {
        out[31] = 1;
        out[44..64].copy_from_slice(authorizer);
    }
    out
}

fn encode_abi_string(s: &str) -> Vec<u8> {
    let raw = s.as_bytes();
    let padded_len = ((raw.len() + 31) / 32) * 32;
    let mut out = vec![0u8; 64 + padded_len];
    out[31] = 32;
    out[56..64].copy_from_slice(&(raw.len() as u64).to_be_bytes());
    out[64..64 + raw.len()].copy_from_slice(raw);
    out
}

/// Dispatches raw EVM/Stylus ABI calldata matching `IMandateVerifier.sol`.
pub fn dispatch_evm_calldata(calldata: &[u8]) -> Result<Vec<u8>, u8> {
    if calldata.len() < 4 {
        return Err(1);
    }
    let sel = [calldata[0], calldata[1], calldata[2], calldata[3]];
    let args = &calldata[4..];

    let verify_sel = selector("verifyMandate(bytes32,bytes,bytes)");
    let scheme_sel = selector("verifierScheme()");

    if sel == verify_sel {
        if args.len() < 96 {
            return Err(2);
        }
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&args[0..32]);

        let sig_slice = decode_abi_bytes(args, 32).ok_or(3u8)?;
        let ctx_slice = decode_abi_bytes(args, 64).ok_or(4u8)?;

        if sig_slice.len() != 64 || ctx_slice.len() != 32 {
            return Ok(encode_verify_response(false, &[0u8; 20]));
        }

        let mut sig = [0u8; 64];
        sig.copy_from_slice(sig_slice);
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(ctx_slice);

        let is_valid = ed25519_verify(&pubkey, &digest, &sig);
        if !is_valid {
            return Ok(encode_verify_response(false, &[0u8; 20]));
        }
        let authorizer = derive_authorizer_address(&pubkey);
        Ok(encode_verify_response(true, &authorizer))
    } else if sel == scheme_sel {
        Ok(encode_abi_string(VERIFIER_SCHEME))
    } else {
        Err(0xff)
    }
}

/// Arbitrum Stylus WASM `user_entrypoint` binding (`wasm32-unknown-unknown` target).
#[cfg(all(target_arch = "wasm32", feature = "stylus-wasm"))]
mod wasm_hostio {
    use super::dispatch_evm_calldata;

    #[link(wasm_import_module = "vm_hooks")]
    extern "C" {
        fn read_args(dest: *mut u8);
        fn write_result(data: *const u8, len: usize);
        fn pay_for_memory_grow(pages: u16);
    }

    #[no_mangle]
    pub extern "C" fn mark_used() {
        unsafe { pay_for_memory_grow(0) };
    }

    #[no_mangle]
    pub extern "C" fn user_entrypoint(args_len: usize) -> usize {
        let mut input = vec![0u8; args_len];
        unsafe { read_args(input.as_mut_ptr()) };
        match dispatch_evm_calldata(&input) {
            Ok(output) => {
                unsafe { write_result(output.as_ptr(), output.len()) };
                0
            }
            Err(_) => 1,
        }
    }
}

/// Convenience helper for generating ABI-encoded `verifyMandate(bytes32,bytes,bytes)` calldata.
pub fn encode_verify_mandate_call(mandate_digest: &[u8; 32], signature: &[u8; 64], pubkey: &[u8; 32]) -> Vec<u8> {
    let sel = selector("verifyMandate(bytes32,bytes,bytes)");
    let mut out = Vec::with_capacity(4 + 32 * 8);
    out.extend_from_slice(&sel);
    // arg 0: bytes32 mandateDigest
    out.extend_from_slice(mandate_digest);
    // arg 1: offset to signature bytes = 0x60 (96)
    out.extend_from_slice(&pad_u64(96));
    // arg 2: offset to verifierContext bytes = 0x60 + 32 + 64 = 192 (0xc0)
    out.extend_from_slice(&pad_u64(192));
    // signature: length 64 + 64 bytes
    out.extend_from_slice(&pad_u64(64));
    out.extend_from_slice(signature);
    // verifierContext: length 32 + 32 bytes
    out.extend_from_slice(&pad_u64(32));
    out.extend_from_slice(pubkey);
    out
}

pub fn sign_ap2_digest_ed25519(secret_seed: &[u8; 32], digest: &[u8; 32]) -> ([u8; 32], [u8; 64], [u8; 20]) {
    let pubkey = ed25519_public_key(secret_seed);
    let sig = ed25519_sign(secret_seed, digest);
    let authorizer = derive_authorizer_address(&pubkey);
    (pubkey, sig, authorizer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..clean.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn test_keccak256_ethereum_vectors() {
        let empty = keccak256(b"");
        assert_eq!(
            empty.to_vec(),
            unhex("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        );

        let transfer_sel = selector("transfer(address,uint256)");
        assert_eq!(transfer_sel, [0xa9, 0x05, 0x9c, 0xbb]);
    }

    #[test]
    fn test_rfc8032_official_vector_1_empty_msg() {
        // IETF RFC 8032 Section 7.1 TEST 1
        let seed_vec = unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let expected_pk = unhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let expected_sig = unhex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        );

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_vec);

        let pk = ed25519_public_key(&seed);
        assert_eq!(pk.to_vec(), expected_pk);

        let sig = ed25519_sign(&seed, b"");
        assert_eq!(sig.to_vec(), expected_sig);
        assert!(ed25519_verify(&pk, b"", &sig));
    }

    #[test]
    fn test_rfc8032_official_vector_2_one_byte_msg() {
        // IETF RFC 8032 Section 7.1 TEST 2 (message = 0x72)
        let seed_vec = unhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
        let expected_pk = unhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        let expected_sig = unhex(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
             085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        );

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_vec);
        let pk = ed25519_public_key(&seed);
        assert_eq!(pk.to_vec(), expected_pk);

        let sig = ed25519_sign(&seed, &[0x72]);
        assert_eq!(sig.to_vec(), expected_sig);
        assert!(ed25519_verify(&pk, &[0x72], &sig));
        assert!(!ed25519_verify(&pk, &[0x73], &sig));
    }

    #[test]
    fn test_stylus_abi_dispatch_verify_mandate_and_tamper_rejection() {
        let vault_addr = [0x42u8; 20];
        let mandate = Ap2Mandate {
            mandate_id: keccak256(b"mandate-dubai-001"),
            agent: [0x11u8; 20],
            max_per_tx: 10_000_000,         // 10 USDC
            max_rolling_24h: 50_000_000,    // 50 USDC
            valid_after: 1_700_000_000,
            deadline: 1_800_000_000,
            min_provider_reputation_bps: 8000,
            allowed_providers_root: [0u8; 32],
            escrow_threshold: 5_000_000,
            dispute_window_seconds: 1800,
            verifier_override: [0x99u8; 20],
        };

        // Arbitrum Sepolia Chain ID = 421614
        let digest = compute_eip712_mandate_digest(421614, &vault_addr, &mandate);
        let seed = [0x77u8; 32];
        let (pubkey, sig, expected_authorizer) = sign_ap2_digest_ed25519(&seed, &digest);

        let calldata = encode_verify_mandate_call(&digest, &sig, &pubkey);
        let result = dispatch_evm_calldata(&calldata).expect("valid ABI dispatch");
        assert_eq!(result.len(), 64);
        assert_eq!(result[31], 1);
        assert_eq!(&result[44..64], &expected_authorizer);

        // Prompt injection tampering with max_per_tx changes digest -> Stylus verifier MUST return valid = false
        let mut tampered_mandate = mandate.clone();
        tampered_mandate.max_per_tx = 500_000_000;
        let tampered_digest = compute_eip712_mandate_digest(421614, &vault_addr, &tampered_mandate);
        let bad_calldata = encode_verify_mandate_call(&tampered_digest, &sig, &pubkey);
        let bad_result = dispatch_evm_calldata(&bad_calldata).expect("valid ABI dispatch");
        assert_eq!(bad_result[31], 0);
        assert_eq!(&bad_result[44..64], &[0u8; 20]);
    }

    #[test]
    fn test_non_canonical_high_s_malleability_rejected() {
        let seed = [0x24u8; 32];
        let digest = keccak256(b"ap2-malleability-check");
        let (pubkey, mut sig, _) = sign_ap2_digest_ed25519(&seed, &digest);
        // Force top byte of S to 0xff (>= L)
        sig[63] = 0xff;
        assert!(!ed25519_verify(&pubkey, &digest, &sig));
    }

    #[test]
    fn test_verifier_scheme_abi_selector() {
        let sel = selector("verifierScheme()");
        let out = dispatch_evm_calldata(&sel).expect("scheme selector");
        assert!(out.len() >= 96);
        let str_len = out[63] as usize;
        assert_eq!(&out[64..64 + str_len], VERIFIER_SCHEME.as_bytes());
    }
}
