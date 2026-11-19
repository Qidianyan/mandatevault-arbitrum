// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IMandateVerifier} from "./interfaces/IMandateVerifier.sol";

/// @title Eip712MandateVerifier
/// @notice Production Arbitrum One Mainnet implementation of `IMandateVerifier` using non-malleable secp256k1 ECDSA
///         recovery (EIP-2 low-s enforced). Serves as Track A in MandateVault's Dual-Track Verifier Architecture while
///         Arbitrum One maintains the October 2, 2026 Security Council WASM activation pause.
contract Eip712MandateVerifier is IMandateVerifier {
    uint256 private constant SECP256K1N_HALF =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    /// @inheritdoc IMandateVerifier
    function verifyMandate(
        bytes32 mandateDigest,
        bytes calldata signature,
        bytes calldata /* verifierContext */
    ) external pure override returns (bool valid, address authorizer) {
        if (signature.length != 65) {
            return (false, address(0));
        }

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 0x20))
            v := byte(0, calldataload(add(signature.offset, 0x40)))
        }

        if (v < 27) {
            v += 27;
        }
        if (v != 27 && v != 28) {
            return (false, address(0));
        }
        // Enforce EIP-2 lower-half s value to prevent signature malleability
        if (uint256(s) > SECP256K1N_HALF || uint256(s) == 0 || uint256(r) == 0) {
            return (false, address(0));
        }

        address recovered = ecrecover(mandateDigest, v, r, s);
        if (recovered == address(0)) {
            return (false, address(0));
        }
        return (true, recovered);
    }

    /// @inheritdoc IMandateVerifier
    function verifierScheme() external pure override returns (string memory) {
        return "EIP712-SECP256K1-V1";
    }
}
