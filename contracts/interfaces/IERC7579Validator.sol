// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Canonical ERC-4337 EntryPoint v0.7 packed UserOperation struct used by ZeroDev Kernel v3.1+ & ERC-7579.
struct PackedUserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    bytes32 accountGasLimits;
    uint256 preVerificationGas;
    bytes32 gasFees;
    bytes paymasterAndData;
    bytes signature;
}

/// @title IERC7579Module
/// @notice Minimal ERC-7579 modular smart account module lifecycle interface (ZeroDev Kernel v3.1+ / EIP-7702 aligned).
interface IERC7579Module {
    /// @notice Called by the smart account when installing this module.
    function onInstall(bytes calldata data) external;

    /// @notice Called by the smart account when uninstalling this module.
    function onUninstall(bytes calldata data) external;

    /// @notice Returns true if this module supports the specified ERC-7579 module type ID.
    ///         Type IDs: 1 = Validator, 2 = Executor, 3 = Fallback, 4 = Hook.
    function isModuleType(uint256 moduleTypeId) external view returns (bool);

    /// @notice Returns true if the module has been initialized for `smartAccount`.
    function isInitialized(address smartAccount) external view returns (bool);
}

/// @title IERC7579Validator
/// @notice Minimal ERC-7579 Validator Module interface (Module Type ID = 1) compatible with ZeroDev Kernel v3.1+
///         smart accounts and EIP-7702 delegated EOAs on Arbitrum One.
interface IERC7579Validator is IERC7579Module {
    /// @notice Validates an ERC-4337 v0.7 `PackedUserOperation` on behalf of `msg.sender` (the smart account).
    /// @return validationData Packed ERC-4337 validation data:
    ///         `authorizer (160 bits) | validUntil (48 bits) | validAfter (48 bits)`,
    ///         where `authorizer == address(0)` denotes success and `authorizer == address(1)` (`1`) denotes failure.
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) external returns (uint256 validationData);

    /// @notice Validates an ERC-1271 off-chain signature forwarded by the smart account.
    /// @return magicValue `0x1626ba7e` if valid, `0xffffffff` otherwise.
    function isValidSignatureWithSender(
        address sender,
        bytes32 hash,
        bytes calldata signature
    ) external view returns (bytes4 magicValue);
}
