// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IMandateVerifier
/// @notice Pluggable Cryptographic AP2 Mandate Verifier Interface supporting Dual-Track Execution:
///         - Track A (Arbitrum One Mainnet): Native Solidity EIP-712 secp256k1 verifier (`Eip712MandateVerifier.sol`),
///           unaffected by the October 2, 2026 Arbitrum Security Council WASM activation gas cap governance action.
///         - Track B (Arbitrum Sepolia / Orbit Coprocessor): Rust Arbitrum Stylus Ed25519 + AP2 Policy Verifier
///           (`stylus_verifier/`), exposing the exact `verifyMandate(bytes32,bytes,bytes)` selector `0xf45d01ce`
///           (and `verifierScheme()` selector `0x0e4ea9e2`) for hardware enclave & passkey-signed AP2 mandates.
interface IMandateVerifier {
    /// @notice Verifies an AP2 Mandate digest and cryptographic proof.
    /// @param mandateDigest Canonical 32-byte EIP-712 or AP2 domain-separated digest.
    /// @param signature Raw signature bytes (65-byte secp256k1 r||s||v or 64-byte RFC 8032 Ed25519 signature).
    /// @param verifierContext Optional verifier payload (e.g., 32-byte Ed25519 public key mapped to an EVM authorizer).
    /// @return valid True if and only if the cryptographic signature is mathematically valid over `mandateDigest`.
    /// @return authorizer The canonical EVM address (or deterministic key-bound identity) that authorized the mandate.
    function verifyMandate(
        bytes32 mandateDigest,
        bytes calldata signature,
        bytes calldata verifierContext
    ) external view returns (bool valid, address authorizer);

    /// @notice Human-readable identifier of the cryptographic scheme ("EIP712-SECP256K1-V1" or "STYLUS-ED25519-AP2-V1").
    function verifierScheme() external pure returns (string memory);
}
