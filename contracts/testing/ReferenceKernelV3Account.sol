// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC7579Module, IERC7579Validator, PackedUserOperation} from "../interfaces/IERC7579Validator.sol";

/// @title ReferenceKernelV3Account
/// @notice Minimal ERC-7579 / ZeroDev Kernel v3.1-compatible Smart Account harness used exclusively in tests
///         to execute end-to-end ERC-4337 v0.7 `PackedUserOperation` flows against `ZeroDevMandateValidator`
///         and `MandateVault` on the local Arbitrum EVM.
contract ReferenceKernelV3Account {
    uint256 public constant MODULE_TYPE_VALIDATOR = 1;
    bytes32 public constant EXEC_MODE_SINGLE_DEFAULT = bytes32(0);

    error UnauthorizedCaller(address caller);
    error UnsupportedModuleType(uint256 moduleTypeId);
    error ValidatorNotInstalled();
    error UnsupportedMode(bytes32 mode);
    error ExecutionFailed(bytes revertData);

    address public owner;
    address public entryPoint;
    address public installedValidator;

    modifier onlyOwner() {
        if (msg.sender != owner) revert UnauthorizedCaller(msg.sender);
        _;
    }

    modifier onlyEntryPointOrOwner() {
        if (msg.sender != entryPoint && msg.sender != owner) revert UnauthorizedCaller(msg.sender);
        _;
    }

    constructor(address owner_, address entryPoint_) {
        owner = owner_;
        entryPoint = entryPoint_;
    }

    receive() external payable {}

    function installModule(uint256 moduleTypeId, address module, bytes calldata initData) external onlyOwner {
        if (moduleTypeId != MODULE_TYPE_VALIDATOR || !IERC7579Module(module).isModuleType(moduleTypeId)) {
            revert UnsupportedModuleType(moduleTypeId);
        }
        installedValidator = module;
        IERC7579Module(module).onInstall(initData);
    }

    function uninstallModule(uint256 moduleTypeId, address module, bytes calldata deInitData) external onlyOwner {
        if (moduleTypeId != MODULE_TYPE_VALIDATOR || installedValidator != module) {
            revert UnsupportedModuleType(moduleTypeId);
        }
        installedValidator = address(0);
        IERC7579Module(module).onUninstall(deInitData);
    }

    function isModuleInstalled(
        uint256 moduleTypeId,
        address module,
        bytes calldata /* additionalContext */
    ) external view returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR && installedValidator == module;
    }

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 /* missingAccountFunds */
    ) external onlyEntryPointOrOwner returns (uint256 validationData) {
        if (installedValidator == address(0)) revert ValidatorNotInstalled();
        return IERC7579Validator(installedValidator).validateUserOp(userOp, userOpHash);
    }

    /// @notice ERC-7579 `execute(bytes32 mode, bytes executionCalldata)` (`0xe9ae5c53`).
    function execute(bytes32 mode, bytes calldata executionCalldata) external payable onlyEntryPointOrOwner returns (bytes memory) {
        if (mode != EXEC_MODE_SINGLE_DEFAULT) revert UnsupportedMode(mode);
        address target = address(bytes20(executionCalldata[0:20]));
        uint256 value = uint256(bytes32(executionCalldata[20:52]));
        bytes calldata data = executionCalldata[52:];
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        if (!ok) {
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }
        return ret;
    }

    /// @notice Allows the human account owner to invoke validator management methods (e.g., rotate/revoke session keys).
    function executeOwnerCall(address target, bytes calldata data) external onlyOwner returns (bytes memory) {
        (bool ok, bytes memory ret) = target.call(data);
        if (!ok) {
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }
        return ret;
    }

    /// @notice ERC-1271 signature check forwarded to the active ERC-7579 Validator via `isValidSignatureWithSender`.
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        if (installedValidator == address(0)) return 0xffffffff;
        return IERC7579Validator(installedValidator).isValidSignatureWithSender(msg.sender, hash, signature);
    }
}

/// @title ReferenceEntryPointV07
/// @notice Minimal ERC-4337 EntryPoint v0.7 test runner enforcing `ValidationData` (`authorizer`, `validAfter`, `validUntil`)
///         and executing `userOp.callData` against a `ReferenceKernelV3Account`.
contract ReferenceEntryPointV07 {
    error AA24SignatureError();
    error AA22ExpiredOrNotDue(uint48 validAfter, uint48 validUntil, uint256 currentTimestamp);

    event UserOperationExecuted(address indexed sender, bytes32 indexed userOpHash, uint256 validationData);

    function handleSingleOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) external returns (uint256 validationData, bytes memory execReturn) {
        validationData = ReferenceKernelV3Account(payable(userOp.sender)).validateUserOp(userOp, userOpHash, 0);

        address authorizer = address(uint160(validationData));
        uint48 validUntil = uint48(validationData >> 160);
        uint48 validAfter = uint48(validationData >> 208);

        if (authorizer != address(0)) {
            revert AA24SignatureError();
        }
        if (block.timestamp < validAfter || (validUntil != 0 && block.timestamp > validUntil)) {
            revert AA22ExpiredOrNotDue(validAfter, validUntil, block.timestamp);
        }

        (bool ok, bytes memory ret) = userOp.sender.call(userOp.callData);
        if (!ok) {
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }

        emit UserOperationExecuted(userOp.sender, userOpHash, validationData);
        return (validationData, ret);
    }
}
