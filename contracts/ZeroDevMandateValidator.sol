// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC7579Module, IERC7579Validator, PackedUserOperation} from "./interfaces/IERC7579Validator.sol";
import {IERC8004Registry} from "./interfaces/IERC8004Registry.sol";
import {MandateVault} from "./MandateVault.sol";

/// @title ZeroDevMandateValidator
/// @author MandateVault Protocol (Arbitrum Open House Buildathon)
/// @notice ERC-7579 Modular Smart Account Validator (Module Type 1) connecting ZeroDev Kernel v3.1+ & EIP-7702
///         ephemeral AI Agent session keys directly to `MandateVault`'s on-chain rolling 24-hour spend cap,
///         sorted-pair Merkle provider allowlist, and live `ERC8004AgentRegistry` reputation gate.
///
///         Security properties enforced at the ERC-4337 `validateUserOp` boundary:
///         1. Strict EIP-2 low-`s` non-malleable `secp256k1` ECDSA verification (supports raw `userOpHash` and
///            EIP-191 `eth_sign` wrapped hashes for ZeroDev SDK & hardware-signer compatibility).
///         2. Uninstall epoch isolation (`installEpoch`): uninstalling the module invalidates all prior session keys
///            in O(1), preventing stale-session resurrection on re-install.
///         3. Strict ERC-7579 `execute(bytes32 mode, bytes executionCalldata)` (`0xe9ae5c53`) inspection:
///            - Only `CALLTYPE_SINGLE | EXECTYPE_DEFAULT` (`bytes32(0)`) is permitted; `CALLTYPE_DELEGATECALL` (`0xff`)
///              and uninspected `CALLTYPE_BATCH` (`0x01`) are deterministically rejected.
///            - Enforces `value == 0` (blocks native ETH drain) and `target == session.mandateVault`.
///            - Only `MandateVault.settleX402Payment` (and optionally defensive `MandateVault.raiseDispute`) selectors
///              are permitted; privileged owner functions (`withdrawPrincipal`, `harvestYield`, `emergencyExitAave`,
///              `setPaused`, etc.) are unconditionally blocked.
///         4. Live cross-contract validation against `MandateVault` & `ERC8004AgentRegistry`:
///            - Verifies vault is unpaused, AP2 mandate is unrevoked, `paymentNonce` is unused, and `mandate.agent`
///              matches the Kernel smart account (`userOp.sender`).
///            - Enforces session per-tx ceiling, vault principal sufficiency (ring-fencing owner Aave V3 yield),
///              and live 86,400-second rolling spend headroom (`getRolling24hSpend` & `getGlobalRolling24hSpend`).
///            - Enforces sorted-pair Merkle allowlist proof and live ERC-8004 provider eligibility & reputation bps.
///         5. Returns ERC-4337 packed `ValidationData` intersecting the session key's and AP2 mandate's
///            `[validAfter, validUntil]` validity windows for native EntryPoint v0.7 enforcement.
contract ZeroDevMandateValidator is IERC7579Validator {
    // -------------------------------------------------------------------------
    // ERC-7579 / ERC-4337 / ERC-1271 Canonical Constants
    // -------------------------------------------------------------------------
    uint256 public constant MODULE_TYPE_VALIDATOR = 1;
    uint256 public constant VALIDATION_SUCCESS = 0;
    uint256 public constant VALIDATION_FAILED = 1;

    bytes4 public constant ERC1271_MAGIC_VALUE = 0x1626ba7e;
    bytes4 public constant ERC1271_INVALID = 0xffffffff;

    /// @dev `bytes4(keccak256("execute(bytes32,bytes)"))` per ERC-7579 `IERC7579Account`.
    bytes4 public constant ERC7579_EXECUTE_SELECTOR = 0xe9ae5c53;

    /// @dev `CALLTYPE_SINGLE (0x00) | EXECTYPE_DEFAULT (0x00) | MODE_DEFAULT (0x00...)`.
    bytes32 public constant EXEC_MODE_SINGLE_DEFAULT = bytes32(0);

    uint16 public constant MAX_BPS = 10_000;
    uint256 private constant SECP256K1N_HALF =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    // -------------------------------------------------------------------------
    // Custom Deterministic Errors
    // -------------------------------------------------------------------------
    error AlreadyInitialized(address smartAccount);
    error NotInitialized(address smartAccount);
    error SmartAccountMismatch(address caller, address userOpSender);
    error InvalidZeroAddress();
    error InvalidSessionCaps(uint256 maxPerTx, uint256 maxRolling24h);
    error InvalidReputationThreshold(uint16 bps);
    error InvalidValidityWindow(uint48 validAfter, uint48 validUntil);
    error MalformedExecutionCalldata();
    error DisallowedOuterSelector(bytes4 selector);
    error UnsupportedExecMode(bytes32 mode);
    error NonZeroCallValue(uint256 value);
    error DisallowedTarget(address target, address expectedVault);
    error DisallowedSelector(bytes4 selector);
    error AgentAccountMismatch(address mandateAgent, address smartAccount);
    error MandateIdMismatch(bytes32 providedMandateId, bytes32 boundMandateId);
    error VaultCurrentlyPaused(address vault);
    error MandateAlreadyRevoked(bytes32 mandateId);
    error PaymentNonceAlreadyUsed(bytes32 paymentNonce);
    error BelowMinimumSettlement(uint256 requested, uint256 minimum);
    error InsufficientVaultPrincipal(uint256 requested, uint256 availablePrincipal);
    error SessionPerTxCapExceeded(uint256 requested, uint256 sessionMaxPerTx);
    error SessionRolling24hCapExceeded(uint256 projectedSpend, uint256 sessionMaxRolling24h, uint64 nextExpiry);
    error GlobalRolling24hCapExceeded(uint256 projectedSpend, uint256 globalMaxRolling24h, uint64 nextExpiry);
    error UnauthorizedProvider(address provider);
    error InsufficientProviderReputation(address provider, uint16 actualBps, uint16 requiredBps);
    error InvalidEscrowId(uint256 escrowId);
    error SessionKeyNotFound(address sessionKey);

    // -------------------------------------------------------------------------
    // Data Structures
    // -------------------------------------------------------------------------

    /// @notice Initialization payload passed to `onInstall(abi.encode(SessionInitConfig))` or `registerSessionKey`.
    struct SessionInitConfig {
        address mandateVault;
        address sessionKey;
        bytes32 boundMandateId;
        uint256 maxPerTx;
        uint256 maxRolling24h;
        uint48 validAfter;
        uint48 validUntil;
        uint16 minProviderReputationBps;
        bytes32 allowedProvidersRoot;
        bool allowDisputeFiling;
    }

    /// @notice Stored per-account, per-epoch session key policy.
    struct SessionPolicy {
        bool active;
        bool revoked;
        bool allowDisputeFiling;
        uint16 minProviderReputationBps;
        uint48 validAfter;
        uint48 validUntil;
        address mandateVault;
        bytes32 boundMandateId;
        bytes32 allowedProvidersRoot;
        uint256 maxPerTx;
        uint256 maxRolling24h;
    }

    struct AccountConfig {
        bool initialized;
        uint64 installEpoch;
        address defaultMandateVault;
        address primarySessionKey;
    }

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------
    event MandateSessionInstalled(
        address indexed smartAccount,
        uint64 indexed installEpoch,
        address indexed sessionKey,
        address mandateVault,
        bytes32 boundMandateId,
        uint256 maxPerTx,
        uint256 maxRolling24h,
        uint48 validAfter,
        uint48 validUntil
    );
    event MandateSessionUninstalled(address indexed smartAccount, uint64 indexed installEpoch);
    event SessionKeyRegistered(
        address indexed smartAccount,
        uint64 indexed installEpoch,
        address indexed sessionKey,
        address mandateVault,
        bytes32 boundMandateId,
        uint256 maxPerTx,
        uint256 maxRolling24h
    );
    event SessionKeyRevoked(address indexed smartAccount, uint64 indexed installEpoch, address indexed sessionKey);

    // -------------------------------------------------------------------------
    // Storage
    // -------------------------------------------------------------------------
    mapping(address => AccountConfig) private _accounts;
    mapping(address => mapping(uint64 => mapping(address => SessionPolicy))) private _sessions;

    // -------------------------------------------------------------------------
    // ERC-7579 Module Lifecycle (`IERC7579Module`)
    // -------------------------------------------------------------------------

    /// @inheritdoc IERC7579Module
    function onInstall(bytes calldata data) external override {
        AccountConfig storage acct = _accounts[msg.sender];
        if (acct.initialized) revert AlreadyInitialized(msg.sender);

        SessionInitConfig memory cfg = abi.decode(data, (SessionInitConfig));
        _validateSessionConfig(cfg);

        uint64 newEpoch = acct.installEpoch + 1;
        acct.initialized = true;
        acct.installEpoch = newEpoch;
        acct.defaultMandateVault = cfg.mandateVault;
        acct.primarySessionKey = cfg.sessionKey;

        _storeSession(msg.sender, newEpoch, cfg);

        emit MandateSessionInstalled(
            msg.sender,
            newEpoch,
            cfg.sessionKey,
            cfg.mandateVault,
            cfg.boundMandateId,
            cfg.maxPerTx,
            cfg.maxRolling24h,
            cfg.validAfter,
            cfg.validUntil
        );
    }

    /// @inheritdoc IERC7579Module
    function onUninstall(bytes calldata /* data */) external override {
        AccountConfig storage acct = _accounts[msg.sender];
        if (!acct.initialized) revert NotInitialized(msg.sender);

        uint64 closedEpoch = acct.installEpoch;
        acct.initialized = false;
        acct.defaultMandateVault = address(0);
        acct.primarySessionKey = address(0);

        emit MandateSessionUninstalled(msg.sender, closedEpoch);
    }

    /// @inheritdoc IERC7579Module
    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }

    /// @inheritdoc IERC7579Module
    function isInitialized(address smartAccount) external view override returns (bool) {
        return _accounts[smartAccount].initialized;
    }

    // -------------------------------------------------------------------------
    // Smart-Account Session Key Rotation & Revocation
    // -------------------------------------------------------------------------

    /// @notice Registers or updates an additional scoped session key for the calling smart account.
    function registerSessionKey(SessionInitConfig calldata cfg) external {
        AccountConfig storage acct = _accounts[msg.sender];
        if (!acct.initialized) revert NotInitialized(msg.sender);

        SessionInitConfig memory memCfg = cfg;
        _validateSessionConfig(memCfg);
        _storeSession(msg.sender, acct.installEpoch, memCfg);

        emit SessionKeyRegistered(
            msg.sender,
            acct.installEpoch,
            cfg.sessionKey,
            cfg.mandateVault,
            cfg.boundMandateId,
            cfg.maxPerTx,
            cfg.maxRolling24h
        );
    }

    /// @notice Immediately revokes a session key for the calling smart account.
    function revokeSessionKey(address sessionKey) external {
        AccountConfig storage acct = _accounts[msg.sender];
        if (!acct.initialized) revert NotInitialized(msg.sender);

        SessionPolicy storage policy = _sessions[msg.sender][acct.installEpoch][sessionKey];
        if (!policy.active && !policy.revoked) revert SessionKeyNotFound(sessionKey);

        policy.active = false;
        policy.revoked = true;

        emit SessionKeyRevoked(msg.sender, acct.installEpoch, sessionKey);
    }

    // -------------------------------------------------------------------------
    // ERC-7579 Validation (`IERC7579Validator`)
    // -------------------------------------------------------------------------

    /// @inheritdoc IERC7579Validator
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) external view override returns (uint256 validationData) {
        if (msg.sender != userOp.sender) {
            revert SmartAccountMismatch(msg.sender, userOp.sender);
        }

        AccountConfig storage acct = _accounts[msg.sender];
        if (!acct.initialized) {
            return VALIDATION_FAILED;
        }

        // 1. Recover session key with strict EIP-2 non-malleable secp256k1 ECDSA
        address matchedSessionKey = _resolveActiveSessionSigner(
            msg.sender,
            acct.installEpoch,
            userOpHash,
            userOp.signature
        );
        if (matchedSessionKey == address(0)) {
            return VALIDATION_FAILED;
        }

        SessionPolicy storage policy = _sessions[msg.sender][acct.installEpoch][matchedSessionKey];

        // 2. Decode & enforce ERC-7579 single-call execution envelope (blocks delegatecall, batch smuggling, ETH drain)
        (address target, uint256 value, bytes calldata innerCallData) = _decodeStrictSingleExecution(userOp.callData);

        if (value != 0) {
            revert NonZeroCallValue(value);
        }
        if (target != policy.mandateVault) {
            revert DisallowedTarget(target, policy.mandateVault);
        }

        bytes4 innerSelector = bytes4(innerCallData[0:4]);

        if (innerSelector == MandateVault.settleX402Payment.selector) {
            return _validateSettleX402UserOp(msg.sender, policy, innerCallData[4:]);
        }

        if (innerSelector == MandateVault.raiseDispute.selector && policy.allowDisputeFiling) {
            (uint256 escrowId,,) = abi.decode(innerCallData[4:], (uint256, bytes32, string));
            if (escrowId == 0) revert InvalidEscrowId(escrowId);
            return _packValidationData(false, policy.validUntil, policy.validAfter);
        }

        revert DisallowedSelector(innerSelector);
    }

    /// @inheritdoc IERC7579Validator
    function isValidSignatureWithSender(
        address /* sender */,
        bytes32 hash,
        bytes calldata signature
    ) external view override returns (bytes4) {
        AccountConfig storage acct = _accounts[msg.sender];
        if (!acct.initialized) {
            return ERC1271_INVALID;
        }

        address matchedSessionKey = _resolveActiveSessionSigner(
            msg.sender,
            acct.installEpoch,
            hash,
            signature
        );
        if (matchedSessionKey == address(0)) {
            return ERC1271_INVALID;
        }

        SessionPolicy storage policy = _sessions[msg.sender][acct.installEpoch][matchedSessionKey];

        if (block.timestamp < policy.validAfter) {
            return ERC1271_INVALID;
        }
        if (policy.validUntil != 0 && block.timestamp > policy.validUntil) {
            return ERC1271_INVALID;
        }

        MandateVault vault = MandateVault(policy.mandateVault);
        if (vault.paused()) {
            return ERC1271_INVALID;
        }
        if (policy.boundMandateId != bytes32(0) && vault.revokedMandates(policy.boundMandateId)) {
            return ERC1271_INVALID;
        }

        return ERC1271_MAGIC_VALUE;
    }

    // -------------------------------------------------------------------------
    // View Helpers & Introspection
    // -------------------------------------------------------------------------

    function validatorScheme() external pure returns (string memory) {
        return "ZERODEV-KERNEL-ERC7579-MANDATE-VALIDATOR-V1";
    }

    function getAccountConfig(address smartAccount)
        external
        view
        returns (
            bool initialized,
            uint64 installEpoch,
            address defaultMandateVault,
            address primarySessionKey
        )
    {
        AccountConfig storage acct = _accounts[smartAccount];
        return (acct.initialized, acct.installEpoch, acct.defaultMandateVault, acct.primarySessionKey);
    }

    function getSessionPolicy(address smartAccount, address sessionKey)
        external
        view
        returns (SessionPolicy memory policy)
    {
        AccountConfig storage acct = _accounts[smartAccount];
        if (!acct.initialized) {
            return policy;
        }
        return _sessions[smartAccount][acct.installEpoch][sessionKey];
    }

    function parseValidationData(uint256 validationData)
        external
        pure
        returns (address authorizer, uint48 validUntil, uint48 validAfter)
    {
        authorizer = address(uint160(validationData));
        validUntil = uint48(validationData >> 160);
        validAfter = uint48(validationData >> 208);
    }

    // -------------------------------------------------------------------------
    // Internal Policy Enforcement & Cryptographic Helpers
    // -------------------------------------------------------------------------

    function _validateSettleX402UserOp(
        address smartAccount,
        SessionPolicy storage policy,
        bytes calldata encodedArgs
    ) private view returns (uint256 validationData) {
        (
            MandateVault.Mandate memory mandate,
            ,
            ,
            MandateVault.X402SettlementRequest memory req
        ) = abi.decode(
            encodedArgs,
            (MandateVault.Mandate, bytes, bytes, MandateVault.X402SettlementRequest)
        );

        if (mandate.agent != smartAccount) {
            revert AgentAccountMismatch(mandate.agent, smartAccount);
        }
        if (policy.boundMandateId != bytes32(0) && mandate.mandateId != policy.boundMandateId) {
            revert MandateIdMismatch(mandate.mandateId, policy.boundMandateId);
        }

        MandateVault vault = MandateVault(policy.mandateVault);
        if (vault.paused()) {
            revert VaultCurrentlyPaused(policy.mandateVault);
        }
        if (vault.revokedMandates(mandate.mandateId)) {
            revert MandateAlreadyRevoked(mandate.mandateId);
        }
        if (vault.usedPaymentNonces(req.paymentNonce)) {
            revert PaymentNonceAlreadyUsed(req.paymentNonce);
        }

        // Enforce per-transaction bounds & ring-fenced principal sufficiency
        uint256 minSettlement = vault.minSettlementUsdc();
        if (req.amount < minSettlement) {
            revert BelowMinimumSettlement(req.amount, minSettlement);
        }
        if (req.amount > policy.maxPerTx || req.amount > mandate.maxPerTx) {
            uint256 effectivePerTx = policy.maxPerTx < mandate.maxPerTx ? policy.maxPerTx : mandate.maxPerTx;
            revert SessionPerTxCapExceeded(req.amount, effectivePerTx);
        }
        uint256 availablePrincipal = vault.principalDeposited();
        if (req.amount > availablePrincipal) {
            revert InsufficientVaultPrincipal(req.amount, availablePrincipal);
        }

        // Enforce true 86,400-second rolling 24h window against live MandateVault spend state
        (uint256 mandateActive24h,, uint64 mandateNextExpiry) = vault.getRolling24hSpend(mandate.mandateId);
        uint256 effectiveRollingCap = policy.maxRolling24h < mandate.maxRolling24h
            ? policy.maxRolling24h
            : mandate.maxRolling24h;
        if (mandateActive24h + req.amount > effectiveRollingCap) {
            revert SessionRolling24hCapExceeded(mandateActive24h + req.amount, effectiveRollingCap, mandateNextExpiry);
        }

        (uint256 globalActive24h,, uint64 globalNextExpiry) = vault.getGlobalRolling24hSpend();
        uint256 globalCap = vault.globalMaxRolling24h();
        if (globalActive24h + req.amount > globalCap) {
            revert GlobalRolling24hCapExceeded(globalActive24h + req.amount, globalCap, globalNextExpiry);
        }

        // Enforce sorted-pair Merkle allowlist (exact leaf parity with MandateVault.sol)
        if (policy.allowedProvidersRoot != bytes32(0)) {
            bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(req.provider, req.categoryHash))));
            if (!_verifyMerkleProof(req.merkleProof, policy.allowedProvidersRoot, leaf)) {
                revert UnauthorizedProvider(req.provider);
            }
        }

        // Enforce live ERC-8004 identity, capability, and reputation threshold
        uint16 requiredRepBps = policy.minProviderReputationBps > mandate.minProviderReputationBps
            ? policy.minProviderReputationBps
            : mandate.minProviderReputationBps;

        address registry = vault.erc8004Registry();
        (bool eligible, uint16 actualRepBps) = IERC8004Registry(registry).checkProviderEligibility(
            req.provider,
            requiredRepBps,
            req.categoryHash
        );
        if (!eligible) {
            revert InsufficientProviderReputation(req.provider, actualRepBps, requiredRepBps);
        }

        // Intersect session key & AP2 mandate time bounds for ERC-4337 EntryPoint enforcement
        (uint48 effectiveValidAfter, uint48 effectiveValidUntil) = _intersectTimeBounds(
            policy.validAfter,
            policy.validUntil,
            mandate.validAfter,
            mandate.deadline
        );

        return _packValidationData(false, effectiveValidUntil, effectiveValidAfter);
    }

    function _decodeStrictSingleExecution(bytes calldata callData)
        private
        pure
        returns (address target, uint256 value, bytes calldata innerCallData)
    {
        if (callData.length < 68) {
            revert MalformedExecutionCalldata();
        }
        bytes4 outerSelector = bytes4(callData[0:4]);
        if (outerSelector != ERC7579_EXECUTE_SELECTOR) {
            revert DisallowedOuterSelector(outerSelector);
        }

        bytes32 mode = bytes32(callData[4:36]);
        if (mode != EXEC_MODE_SINGLE_DEFAULT) {
            revert UnsupportedExecMode(mode);
        }

        uint256 relOffset = uint256(bytes32(callData[36:68]));
        if (relOffset < 64 || relOffset > callData.length || callData.length - relOffset < 36) {
            revert MalformedExecutionCalldata();
        }

        uint256 lenPos = 4 + relOffset;
        uint256 execLen = uint256(bytes32(callData[lenPos : lenPos + 32]));
        uint256 dataStart = lenPos + 32;
        if (execLen > callData.length - dataStart || execLen < 56) {
            revert MalformedExecutionCalldata();
        }

        bytes calldata execBytes = callData[dataStart : dataStart + execLen];
        target = address(bytes20(execBytes[0:20]));
        value = uint256(bytes32(execBytes[20:52]));
        innerCallData = execBytes[52:];
    }

    function _resolveActiveSessionSigner(
        address smartAccount,
        uint64 installEpoch,
        bytes32 hash,
        bytes calldata signature
    ) private view returns (address) {
        if (signature.length != 65) {
            return address(0);
        }

        (bool parsed, bytes32 r, bytes32 s, uint8 v) = _parseNonMalleableSig(signature);
        if (!parsed) {
            return address(0);
        }

        address directSigner = ecrecover(hash, v, r, s);
        if (directSigner != address(0)) {
            SessionPolicy storage pDirect = _sessions[smartAccount][installEpoch][directSigner];
            if (pDirect.active && !pDirect.revoked) {
                return directSigner;
            }
        }

        bytes32 ethSignedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
        address ethSigner = ecrecover(ethSignedHash, v, r, s);
        if (ethSigner != address(0)) {
            SessionPolicy storage pEth = _sessions[smartAccount][installEpoch][ethSigner];
            if (pEth.active && !pEth.revoked) {
                return ethSigner;
            }
        }

        return address(0);
    }

    function _parseNonMalleableSig(bytes calldata signature)
        private
        pure
        returns (bool ok, bytes32 r, bytes32 s, uint8 v)
    {
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 0x20))
            v := byte(0, calldataload(add(signature.offset, 0x40)))
        }
        if (v < 27) {
            v += 27;
        }
        if (v != 27 && v != 28) {
            return (false, bytes32(0), bytes32(0), 0);
        }
        if (uint256(s) > SECP256K1N_HALF || uint256(s) == 0 || uint256(r) == 0) {
            return (false, bytes32(0), bytes32(0), 0);
        }
        return (true, r, s, v);
    }

    function _validateSessionConfig(SessionInitConfig memory cfg) private view {
        if (cfg.mandateVault == address(0) || cfg.sessionKey == address(0)) {
            revert InvalidZeroAddress();
        }
        if (cfg.maxPerTx == 0 || cfg.maxRolling24h == 0 || cfg.maxPerTx > cfg.maxRolling24h) {
            revert InvalidSessionCaps(cfg.maxPerTx, cfg.maxRolling24h);
        }
        if (cfg.minProviderReputationBps > MAX_BPS) {
            revert InvalidReputationThreshold(cfg.minProviderReputationBps);
        }
        if (cfg.validUntil != 0 && cfg.validUntil <= cfg.validAfter) {
            revert InvalidValidityWindow(cfg.validAfter, cfg.validUntil);
        }
        // Confirm target is a live MandateVault wired to an ERC-8004 registry
        if (MandateVault(cfg.mandateVault).erc8004Registry() == address(0)) {
            revert InvalidZeroAddress();
        }
    }

    function _storeSession(address smartAccount, uint64 epoch, SessionInitConfig memory cfg) private {
        _sessions[smartAccount][epoch][cfg.sessionKey] = SessionPolicy({
            active: true,
            revoked: false,
            allowDisputeFiling: cfg.allowDisputeFiling,
            minProviderReputationBps: cfg.minProviderReputationBps,
            validAfter: cfg.validAfter,
            validUntil: cfg.validUntil,
            mandateVault: cfg.mandateVault,
            boundMandateId: cfg.boundMandateId,
            allowedProvidersRoot: cfg.allowedProvidersRoot,
            maxPerTx: cfg.maxPerTx,
            maxRolling24h: cfg.maxRolling24h
        });
    }

    function _intersectTimeBounds(
        uint48 sessionValidAfter,
        uint48 sessionValidUntil,
        uint64 mandateValidAfter,
        uint64 mandateDeadline
    ) private pure returns (uint48 effectiveAfter, uint48 effectiveUntil) {
        if (mandateValidAfter > type(uint48).max) {
            revert InvalidValidityWindow(type(uint48).max, sessionValidUntil);
        }
        uint48 mAfter = uint48(mandateValidAfter);
        uint48 mUntil = mandateDeadline > type(uint48).max ? type(uint48).max : uint48(mandateDeadline);

        effectiveAfter = sessionValidAfter > mAfter ? sessionValidAfter : mAfter;

        if (sessionValidUntil == 0) {
            effectiveUntil = mUntil;
        } else if (mUntil == 0) {
            effectiveUntil = sessionValidUntil;
        } else {
            effectiveUntil = sessionValidUntil < mUntil ? sessionValidUntil : mUntil;
        }

        if (effectiveUntil != 0 && effectiveUntil < effectiveAfter) {
            revert InvalidValidityWindow(effectiveAfter, effectiveUntil);
        }
    }

    function _packValidationData(
        bool sigFailed,
        uint48 validUntil,
        uint48 validAfter
    ) private pure returns (uint256) {
        return (sigFailed ? uint256(1) : uint256(0))
            | (uint256(validUntil) << 160)
            | (uint256(validAfter) << 208);
    }

    function _verifyMerkleProof(
        bytes32[] memory proof,
        bytes32 root,
        bytes32 leaf
    ) private pure returns (bool) {
        bytes32 computedHash = leaf;
        for (uint256 i = 0; i < proof.length; ++i) {
            bytes32 proofElement = proof[i];
            if (computedHash <= proofElement) {
                computedHash = keccak256(abi.encodePacked(computedHash, proofElement));
            } else {
                computedHash = keccak256(abi.encodePacked(proofElement, computedHash));
            }
        }
        return computedHash == root;
    }
}
