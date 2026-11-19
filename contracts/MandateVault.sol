// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "./interfaces/IERC20.sol";
import {IAaveV3Pool} from "./interfaces/IAaveV3Pool.sol";
import {IERC8004Registry} from "./interfaces/IERC8004Registry.sol";
import {IMandateVerifier} from "./interfaces/IMandateVerifier.sol";
import {SafeTransferLib} from "./libraries/SafeTransferLib.sol";

/// @title MandateVault
/// @author MandateVault Protocol (Arbitrum Open House Buildathon)
/// @notice Non-custodial AP2 x x402 x ERC-8004 Zero-Idle Aave V3 Yield Settlement Vault on Arbitrum One.
///         - Idle capital is supplied 100% into Arbitrum One Aave V3 Pool (`0x794a61358D6845594F94dc1DB02A252b5b4814aD`)
///           for Native USDC (`0xaf88d065e77c8cC2239327C5EDb3A432268e5831`), accruing real `aArbUSDCn` yield.
///         - Authorized AI Agents settle HTTP `402 Payment Required` challenges via single-transaction atomic principal
///           redemption (`aavePool.withdraw`), while 100% of accrued interest remains in `aArbUSDCn` for the Vault Owner.
///         - Deterministically reverts on over-limit spend, Sybil split-order attacks (true 86,400s sliding window),
///           prompt-injected unauthorized recipients, or low-reputation ERC-8004 service providers.
///         - Supports Optimistic Dispute Timelock Escrow with instant principal re-supply into Aave V3 on refund.
contract MandateVault {
    // -------------------------------------------------------------------------
    // Canonical Arbitrum One Mainnet Protocol Constants
    // -------------------------------------------------------------------------
    address public constant ARBITRUM_ONE_USDC = 0xaf88d065e77c8cC2239327C5EDb3A432268e5831;
    address public constant ARBITRUM_ONE_AAVE_V3_POOL = 0x794a61358D6845594F94dc1DB02A252b5b4814aD;

    uint256 public constant ROLLING_WINDOW_SECONDS = 86_400; // Exact 24-hour sliding window
    uint256 public constant DEFAULT_MAX_WINDOW_TX_COUNT = 256;
    uint16 public constant DEFAULT_DISPUTE_SLASH_BPS = 1_500; // 15.00% ERC-8004 slash on confirmed fraud

    bytes32 public constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    bytes32 public constant MANDATE_TYPEHASH =
        keccak256(
            "Mandate(bytes32 mandateId,address agent,uint256 maxPerTx,uint256 maxRolling24h,uint64 validAfter,uint64 deadline,uint16 minProviderReputationBps,bytes32 allowedProvidersRoot,uint256 escrowThreshold,uint64 disputeWindowSeconds,address verifierOverride)"
        );

    bytes32 private constant NAME_HASH = keccak256("MandateVault");
    bytes32 private constant VERSION_HASH = keccak256("1");

    // -------------------------------------------------------------------------
    // Custom Deterministic Errors
    // -------------------------------------------------------------------------
    error UnauthorizedCaller(address caller);
    error VaultPaused();
    error InvalidZeroAddress();
    error InvalidAmount();
    error BelowMinimumSettlement(uint256 amount, uint256 minimum);
    error MandateRevoked(bytes32 mandateId);
    error MandateNotYetValid(uint64 validAfter, uint64 currentTimestamp);
    error MandateExpired(uint64 deadline, uint64 currentTimestamp);
    error CallerNotAuthorizedAgent(address caller, address expectedAgent);
    error UnapprovedVerifier(address verifier);
    error InvalidMandateSignature(address recoveredAuthorizer);
    error PaymentNonceAlreadyUsed(bytes32 paymentNonce);
    error PerTxCapExceeded(uint256 requested, uint256 maxPerTx);
    error Rolling24hWindowCapExceeded(uint256 projectedSpend, uint256 windowCap, uint64 nextSlotExpiry);
    error RollingWindowTxCountExceeded(uint256 activeCount, uint256 maxAllowed);
    error UnauthorizedProvider(address provider);
    error InsufficientProviderReputation(address provider, uint16 actualBps, uint16 requiredBps);
    error InsufficientVaultPrincipal(uint256 requested, uint256 availablePrincipal);
    error NoYieldAvailable();
    error EscrowNotFound(uint256 escrowId);
    error InvalidEscrowState(uint256 escrowId, EscrowStatus currentStatus);
    error DisputeWindowExpired(uint256 escrowId, uint64 unlockAt, uint64 currentTimestamp);
    error DisputeTimelockActive(uint256 escrowId, uint64 unlockAt, uint64 currentTimestamp);
    error ReentrancyDetected();

    // -------------------------------------------------------------------------
    // Data Structures
    // -------------------------------------------------------------------------
    enum EscrowStatus {
        None,
        Locked,
        Disputed,
        Released,
        Refunded
    }

    struct Mandate {
        bytes32 mandateId;
        address agent;
        uint256 maxPerTx;
        uint256 maxRolling24h;
        uint64 validAfter;
        uint64 deadline;
        uint16 minProviderReputationBps;
        bytes32 allowedProvidersRoot;
        uint256 escrowThreshold;
        uint64 disputeWindowSeconds;
        address verifierOverride;
    }

    struct X402SettlementRequest {
        bytes32 paymentNonce;
        address provider;
        uint256 amount;
        bytes32 resourceHash;
        bytes32 expectedPayloadHash;
        bytes32 categoryHash;
        bytes32[] merkleProof;
        bool forceEscrow;
    }

    struct SpendEntry {
        uint64 timestamp;
        uint192 amount;
    }

    struct RollingWindow {
        uint64 head;
        uint192 activeSum;
        SpendEntry[] entries;
    }

    struct EscrowRecord {
        bytes32 mandateId;
        bytes32 paymentNonce;
        address agent;
        address provider;
        uint256 amount;
        uint64 createdAt;
        uint64 unlockAt;
        bytes32 expectedPayloadHash;
        bytes32 observedPayloadHash;
        EscrowStatus status;
    }

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------
    event DepositedToAave(address indexed depositor, uint256 amountUsdc, uint256 newPrincipal);
    event PrincipalWithdrawn(address indexed owner, address indexed recipient, uint256 amountUsdc, uint256 remainingPrincipal);
    event YieldHarvested(address indexed owner, address indexed recipient, uint256 yieldUsdc);
    event X402AtomicSettlement(
        bytes32 indexed mandateId,
        bytes32 indexed paymentNonce,
        address indexed provider,
        address agent,
        uint256 amountUsdc,
        bytes32 resourceHash,
        uint256 mandateRollingSpend24h
    );
    event EscrowCreated(
        uint256 indexed escrowId,
        bytes32 indexed mandateId,
        address indexed provider,
        uint256 amountUsdc,
        uint64 unlockAt,
        bytes32 expectedPayloadHash
    );
    event DisputeRaised(
        uint256 indexed escrowId,
        address indexed challenger,
        bytes32 expectedPayloadHash,
        bytes32 observedPayloadHash,
        string reason
    );
    event DisputeResolved(uint256 indexed escrowId, bool refundedToVault, uint256 amountUsdc);
    event EscrowReleased(uint256 indexed escrowId, address indexed provider, uint256 amountUsdc);
    event MandateRevocationUpdated(bytes32 indexed mandateId, bool revoked);
    event VerifierApprovalUpdated(address indexed verifier, bool approved);
    event DelegatedAuthorizerUpdated(address indexed authorizer, bool authorized);
    event VaultPauseUpdated(bool paused);

    // -------------------------------------------------------------------------
    // Immutables & State Variables
    // -------------------------------------------------------------------------
    address public immutable usdc;
    address public immutable aavePool;
    address public immutable aToken;
    uint256 private immutable _initialChainId;
    bytes32 private immutable _initialDomainSeparator;

    address public owner;
    address public arbitrator;
    address public erc8004Registry;
    address public defaultVerifier;

    bool public paused;
    uint256 private _reentrancyLock = 1;

    uint256 public principalDeposited;
    uint256 public totalEscrowedUsdc;
    uint256 public totalSettledUsdc;
    uint256 public totalHarvestedYieldUsdc;

    uint256 public globalMaxRolling24h;
    uint256 public minSettlementUsdc = 100; // 0.000100 USDC anti-dust floor
    uint256 public maxWindowTxCount = DEFAULT_MAX_WINDOW_TX_COUNT;
    uint16 public disputeSlashBps = DEFAULT_DISPUTE_SLASH_BPS;

    uint256 public escrowCount;

    mapping(address => bool) public approvedVerifiers;
    mapping(address => bool) public delegatedAuthorizers;
    mapping(bytes32 => bool) public revokedMandates;
    mapping(bytes32 => bool) public usedPaymentNonces;
    mapping(uint256 => EscrowRecord) public escrows;

    mapping(bytes32 => RollingWindow) private _mandateWindows;
    RollingWindow private _globalWindow;

    // -------------------------------------------------------------------------
    // Modifiers
    // -------------------------------------------------------------------------
    modifier nonReentrant() {
        if (_reentrancyLock != 1) revert ReentrancyDetected();
        _reentrancyLock = 2;
        _;
        _reentrancyLock = 1;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert UnauthorizedCaller(msg.sender);
        _;
    }

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------
    constructor(
        address owner_,
        address usdc_,
        address aavePool_,
        address erc8004Registry_,
        address defaultVerifier_,
        uint256 globalMaxRolling24h_
    ) {
        if (erc8004Registry_ == address(0) || defaultVerifier_ == address(0)) {
            revert InvalidZeroAddress();
        }
        owner = owner_ == address(0) ? msg.sender : owner_;
        arbitrator = owner;
        usdc = usdc_ == address(0) ? ARBITRUM_ONE_USDC : usdc_;
        aavePool = aavePool_ == address(0) ? ARBITRUM_ONE_AAVE_V3_POOL : aavePool_;
        erc8004Registry = erc8004Registry_;
        defaultVerifier = defaultVerifier_;
        globalMaxRolling24h = globalMaxRolling24h_ == 0 ? type(uint192).max : globalMaxRolling24h_;

        IAaveV3Pool.ReserveData memory reserve = IAaveV3Pool(aavePool).getReserveData(usdc);
        if (reserve.aTokenAddress == address(0)) revert InvalidZeroAddress();
        aToken = reserve.aTokenAddress;

        approvedVerifiers[defaultVerifier_] = true;

        _initialChainId = block.chainid;
        _initialDomainSeparator = _buildDomainSeparator(block.chainid);
    }

    // -------------------------------------------------------------------------
    // Vault Liquidity & Zero-Idle Aave V3 Yield Management
    // -------------------------------------------------------------------------

    /// @notice Deposits USDC and immediately supplies 100% into Arbitrum Aave V3 Pool to earn real `aArbUSDCn` yield.
    function deposit(uint256 amount) external nonReentrant {
        if (paused) revert VaultPaused();
        if (amount == 0) revert InvalidAmount();

        principalDeposited += amount;
        SafeTransferLib.safeTransferFrom(usdc, msg.sender, address(this), amount);
        SafeTransferLib.safeApprove(usdc, aavePool, amount);
        IAaveV3Pool(aavePool).supply(usdc, amount, address(this), 0);

        // Guard against 1-wei Aave V3 WadRayMath rayDiv floor rounding at dt = 0
        uint256 aBalance = IERC20(aToken).balanceOf(address(this));
        if (aBalance < principalDeposited) {
            principalDeposited = aBalance;
        }

        emit DepositedToAave(msg.sender, amount, principalDeposited);
    }

    /// @notice Withdraws unencumbered principal from Aave V3 back to the Vault Owner.
    function withdrawPrincipal(uint256 amount, address recipient) external onlyOwner nonReentrant {
        if (recipient == address(0)) revert InvalidZeroAddress();
        if (amount == 0) revert InvalidAmount();
        if (amount > principalDeposited) revert InsufficientVaultPrincipal(amount, principalDeposited);

        principalDeposited -= amount;
        uint256 withdrawn = IAaveV3Pool(aavePool).withdraw(usdc, amount, recipient);

        emit PrincipalWithdrawn(msg.sender, recipient, withdrawn, principalDeposited);
    }

    /// @notice Harvests 100% of accrued Aave V3 interest (`aToken.balanceOf(this) - principalDeposited`) exclusively to `recipient`.
    function harvestYield(address recipient) external onlyOwner nonReentrant returns (uint256 harvested) {
        if (recipient == address(0)) revert InvalidZeroAddress();
        uint256 aBalance = IERC20(aToken).balanceOf(address(this));
        if (aBalance <= principalDeposited) revert NoYieldAvailable();

        uint256 claimable = aBalance - principalDeposited;
        harvested = IAaveV3Pool(aavePool).withdraw(usdc, claimable, recipient);
        totalHarvestedYieldUsdc += harvested;

        emit YieldHarvested(msg.sender, recipient, harvested);
    }

    /// @notice Emergency full exit: pauses the vault and withdraws all principal + yield from Aave V3 to `owner`.
    function emergencyExitAave(address recipient) external onlyOwner nonReentrant returns (uint256 totalRecovered) {
        if (recipient == address(0)) revert InvalidZeroAddress();
        paused = true;
        emit VaultPauseUpdated(true);

        uint256 aBalance = IERC20(aToken).balanceOf(address(this));
        principalDeposited = 0;
        if (aBalance > 0) {
            totalRecovered = IAaveV3Pool(aavePool).withdraw(usdc, type(uint256).max, recipient);
        }
    }

    // -------------------------------------------------------------------------
    // Core x402 Atomic Redemption & AP2 + ERC-8004 Guarded Settlement
    // -------------------------------------------------------------------------

    /// @notice Settles an HTTP `402 Payment Required` challenge under a human-signed AP2 Mandate.
    ///         Atomically redeems exact `req.amount` principal from Aave V3 while preserving accrued yield for `owner`.
    function settleX402Payment(
        Mandate calldata mandate,
        bytes calldata mandateSignature,
        bytes calldata verifierContext,
        X402SettlementRequest calldata req
    ) external nonReentrant returns (uint256 escrowId) {
        if (paused) revert VaultPaused();
        if (msg.sender != mandate.agent) revert CallerNotAuthorizedAgent(msg.sender, mandate.agent);
        if (revokedMandates[mandate.mandateId]) revert MandateRevoked(mandate.mandateId);
        if (usedPaymentNonces[req.paymentNonce]) revert PaymentNonceAlreadyUsed(req.paymentNonce);
        if (req.provider == address(0)) revert InvalidZeroAddress();
        if (req.amount == 0 || req.amount > type(uint192).max) revert InvalidAmount();
        if (req.amount < minSettlementUsdc) revert BelowMinimumSettlement(req.amount, minSettlementUsdc);

        uint64 nowTs = uint64(block.timestamp);
        if (nowTs < mandate.validAfter) revert MandateNotYetValid(mandate.validAfter, nowTs);
        if (nowTs > mandate.deadline) revert MandateExpired(mandate.deadline, nowTs);

        // 1. Verify AP2 Mandate via Dual-Track Pluggable IMandateVerifier (EIP-712 Mainnet or Stylus Ed25519 Coprocessor)
        address verifier = mandate.verifierOverride == address(0) ? defaultVerifier : mandate.verifierOverride;
        if (!approvedVerifiers[verifier]) revert UnapprovedVerifier(verifier);

        bytes32 digest = computeMandateDigest(mandate);
        (bool sigValid, address authorizer) = IMandateVerifier(verifier).verifyMandate(
            digest,
            mandateSignature,
            verifierContext
        );
        if (!sigValid || (authorizer != owner && !delegatedAuthorizers[authorizer])) {
            revert InvalidMandateSignature(authorizer);
        }

        // 2. Enforce Per-Transaction Spend Ceiling
        if (req.amount > mandate.maxPerTx) {
            revert PerTxCapExceeded(req.amount, mandate.maxPerTx);
        }

        // 3. Enforce AP2 Merchant Allowlist Merkle Proof (if root is specified)
        if (mandate.allowedProvidersRoot != bytes32(0)) {
            bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(req.provider, req.categoryHash))));
            if (!_verifyMerkleProof(req.merkleProof, mandate.allowedProvidersRoot, leaf)) {
                revert UnauthorizedProvider(req.provider);
            }
        }

        // 4. Enforce ERC-8004 On-Chain Service Provider Identity & Reputation Gate
        (bool eligible, uint16 actualRepBps) = IERC8004Registry(erc8004Registry).checkProviderEligibility(
            req.provider,
            mandate.minProviderReputationBps,
            req.categoryHash
        );
        if (!eligible) {
            revert InsufficientProviderReputation(req.provider, actualRepBps, mandate.minProviderReputationBps);
        }

        // 5. Enforce True Rolling 24-Hour Sliding Window Caps (Anti-Sybil Split-Order Attack)
        uint256 newMandateWindowSpend = _recordRollingSpend(
            _mandateWindows[mandate.mandateId],
            req.amount,
            mandate.maxRolling24h
        );
        _recordRollingSpend(_globalWindow, req.amount, globalMaxRolling24h);

        // 6. Enforce Principal Sufficiency (Accrued Yield Is Strictly Ring-Fenced for Vault Owner)
        if (req.amount > principalDeposited) {
            revert InsufficientVaultPrincipal(req.amount, principalDeposited);
        }

        // 7. Commit State Before External Calls (Checks-Effects-Interactions)
        usedPaymentNonces[req.paymentNonce] = true;
        principalDeposited -= req.amount;

        bool routeToEscrow = req.forceEscrow || (mandate.escrowThreshold > 0 && req.amount >= mandate.escrowThreshold);

        if (routeToEscrow) {
            uint64 windowSec = mandate.disputeWindowSeconds == 0 ? 900 : mandate.disputeWindowSeconds;
            uint64 unlockAt = nowTs + windowSec;
            escrowId = ++escrowCount;
            totalEscrowedUsdc += req.amount;

            escrows[escrowId] = EscrowRecord({
                mandateId: mandate.mandateId,
                paymentNonce: req.paymentNonce,
                agent: mandate.agent,
                provider: req.provider,
                amount: req.amount,
                createdAt: nowTs,
                unlockAt: unlockAt,
                expectedPayloadHash: req.expectedPayloadHash,
                observedPayloadHash: bytes32(0),
                status: EscrowStatus.Locked
            });

            IAaveV3Pool(aavePool).withdraw(usdc, req.amount, address(this));
            emit EscrowCreated(escrowId, mandate.mandateId, req.provider, req.amount, unlockAt, req.expectedPayloadHash);
        } else {
            totalSettledUsdc += req.amount;
            uint256 settled = IAaveV3Pool(aavePool).withdraw(usdc, req.amount, req.provider);
            IERC8004Registry(erc8004Registry).recordSettlementSuccess(req.provider, settled);

            emit X402AtomicSettlement(
                mandate.mandateId,
                req.paymentNonce,
                req.provider,
                mandate.agent,
                settled,
                req.resourceHash,
                newMandateWindowSpend
            );
        }
    }

    // -------------------------------------------------------------------------
    // Optimistic Dispute Timelock Escrow Lifecycle
    // -------------------------------------------------------------------------

    /// @notice Freezes an active escrowed x402 payment prior to `unlockAt` when delivered payload fails verification.
    function raiseDispute(
        uint256 escrowId,
        bytes32 observedPayloadHash,
        string calldata reason
    ) external nonReentrant {
        EscrowRecord storage esc = escrows[escrowId];
        if (esc.status == EscrowStatus.None) revert EscrowNotFound(escrowId);
        if (esc.status != EscrowStatus.Locked) revert InvalidEscrowState(escrowId, esc.status);
        if (msg.sender != owner && msg.sender != arbitrator && msg.sender != esc.agent) {
            revert UnauthorizedCaller(msg.sender);
        }
        if (block.timestamp >= esc.unlockAt) {
            revert DisputeWindowExpired(escrowId, esc.unlockAt, uint64(block.timestamp));
        }

        esc.status = EscrowStatus.Disputed;
        esc.observedPayloadHash = observedPayloadHash;

        emit DisputeRaised(escrowId, msg.sender, esc.expectedPayloadHash, observedPayloadHash, reason);
    }

    /// @notice Resolves a frozen dispute. If `refundToVault == true`, re-supplies principal directly into Aave V3
    ///         so capital resumes earning yield immediately, and slashes the provider's ERC-8004 reputation.
    function resolveDispute(uint256 escrowId, bool refundToVault) external nonReentrant {
        if (msg.sender != owner && msg.sender != arbitrator) revert UnauthorizedCaller(msg.sender);

        EscrowRecord storage esc = escrows[escrowId];
        if (esc.status == EscrowStatus.None) revert EscrowNotFound(escrowId);
        if (esc.status != EscrowStatus.Disputed) revert InvalidEscrowState(escrowId, esc.status);

        uint256 amount = esc.amount;
        totalEscrowedUsdc -= amount;

        if (refundToVault) {
            esc.status = EscrowStatus.Refunded;
            principalDeposited += amount;
            SafeTransferLib.safeApprove(usdc, aavePool, amount);
            IAaveV3Pool(aavePool).supply(usdc, amount, address(this), 0);
            uint256 aBalance = IERC20(aToken).balanceOf(address(this));
            if (aBalance < principalDeposited) {
                principalDeposited = aBalance;
            }
            IERC8004Registry(erc8004Registry).recordDisputePenalty(esc.provider, disputeSlashBps);
        } else {
            esc.status = EscrowStatus.Released;
            totalSettledUsdc += amount;
            SafeTransferLib.safeTransfer(usdc, esc.provider, amount);
            IERC8004Registry(erc8004Registry).recordSettlementSuccess(esc.provider, amount);
        }

        emit DisputeResolved(escrowId, refundToVault, amount);
    }

    /// @notice Releases an unchallenged escrow to the service provider once `disputeWindowSeconds` has elapsed.
    function releaseEscrow(uint256 escrowId) external nonReentrant {
        EscrowRecord storage esc = escrows[escrowId];
        if (esc.status == EscrowStatus.None) revert EscrowNotFound(escrowId);
        if (esc.status != EscrowStatus.Locked) revert InvalidEscrowState(escrowId, esc.status);
        if (block.timestamp < esc.unlockAt) {
            revert DisputeTimelockActive(escrowId, esc.unlockAt, uint64(block.timestamp));
        }

        uint256 amount = esc.amount;
        esc.status = EscrowStatus.Released;
        totalEscrowedUsdc -= amount;
        totalSettledUsdc += amount;

        SafeTransferLib.safeTransfer(usdc, esc.provider, amount);
        IERC8004Registry(erc8004Registry).recordSettlementSuccess(esc.provider, amount);

        emit EscrowReleased(escrowId, esc.provider, amount);
    }

    // -------------------------------------------------------------------------
    // Governance & Risk Controls
    // -------------------------------------------------------------------------

    function setMandateRevoked(bytes32 mandateId, bool revoked) external onlyOwner {
        revokedMandates[mandateId] = revoked;
        emit MandateRevocationUpdated(mandateId, revoked);
    }

    function setVerifierApproval(address verifier, bool approved) external onlyOwner {
        if (verifier == address(0)) revert InvalidZeroAddress();
        approvedVerifiers[verifier] = approved;
        emit VerifierApprovalUpdated(verifier, approved);
    }

    function setDefaultVerifier(address verifier) external onlyOwner {
        if (verifier == address(0)) revert InvalidZeroAddress();
        approvedVerifiers[verifier] = true;
        defaultVerifier = verifier;
        emit VerifierApprovalUpdated(verifier, true);
    }

    function setDelegatedAuthorizer(address authorizer, bool authorized) external onlyOwner {
        if (authorizer == address(0)) revert InvalidZeroAddress();
        delegatedAuthorizers[authorizer] = authorized;
        emit DelegatedAuthorizerUpdated(authorizer, authorized);
    }

    function setArbitrator(address newArbitrator) external onlyOwner {
        if (newArbitrator == address(0)) revert InvalidZeroAddress();
        arbitrator = newArbitrator;
    }

    function setGlobalMaxRolling24h(uint256 newCap) external onlyOwner {
        if (newCap == 0) revert InvalidAmount();
        globalMaxRolling24h = newCap;
    }

    function setPaused(bool paused_) external onlyOwner {
        paused = paused_;
        emit VaultPauseUpdated(paused_);
    }

    // -------------------------------------------------------------------------
    // View Telemetry & Cryptographic Helpers
    // -------------------------------------------------------------------------

    function domainSeparator() public view returns (bytes32) {
        return block.chainid == _initialChainId ? _initialDomainSeparator : _buildDomainSeparator(block.chainid);
    }

    function hashMandate(Mandate calldata mandate) public pure returns (bytes32) {
        return keccak256(
            abi.encode(
                MANDATE_TYPEHASH,
                mandate.mandateId,
                mandate.agent,
                mandate.maxPerTx,
                mandate.maxRolling24h,
                mandate.validAfter,
                mandate.deadline,
                mandate.minProviderReputationBps,
                mandate.allowedProvidersRoot,
                mandate.escrowThreshold,
                mandate.disputeWindowSeconds,
                mandate.verifierOverride
            )
        );
    }

    function computeMandateDigest(Mandate calldata mandate) public view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), hashMandate(mandate)));
    }

    function vaultYieldMetrics()
        external
        view
        returns (
            uint256 aTokenBalance,
            uint256 activePrincipal,
            uint256 claimableOwnerYield,
            uint256 escrowedUsdc,
            uint128 currentLiquidityRateRay,
            uint128 liquidityIndexRay
        )
    {
        aTokenBalance = IERC20(aToken).balanceOf(address(this));
        activePrincipal = principalDeposited;
        claimableOwnerYield = aTokenBalance > principalDeposited ? aTokenBalance - principalDeposited : 0;
        escrowedUsdc = totalEscrowedUsdc;

        IAaveV3Pool.ReserveData memory reserve = IAaveV3Pool(aavePool).getReserveData(usdc);
        currentLiquidityRateRay = reserve.currentLiquidityRate;
        liquidityIndexRay = reserve.liquidityIndex;
    }

    function getRolling24hSpend(bytes32 mandateId)
        external
        view
        returns (uint256 activeSpend, uint256 activeTxCount, uint64 nextExpiryTimestamp)
    {
        return _inspectWindow(_mandateWindows[mandateId]);
    }

    function getGlobalRolling24hSpend()
        external
        view
        returns (uint256 activeSpend, uint256 activeTxCount, uint64 nextExpiryTimestamp)
    {
        return _inspectWindow(_globalWindow);
    }

    // -------------------------------------------------------------------------
    // Internal Helpers
    // -------------------------------------------------------------------------

    function _buildDomainSeparator(uint256 chainId) private view returns (bytes32) {
        return keccak256(abi.encode(EIP712_DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, chainId, address(this)));
    }

    function _recordRollingSpend(
        RollingWindow storage win,
        uint256 amount,
        uint256 cap
    ) private returns (uint256 newActiveSpend) {
        uint256 len = win.entries.length;
        uint64 h = win.head;
        uint192 activeSum = win.activeSum;
        uint256 nowTs = block.timestamp;

        while (h < len) {
            SpendEntry storage entry = win.entries[h];
            if (uint256(entry.timestamp) + ROLLING_WINDOW_SECONDS <= nowTs) {
                activeSum -= entry.amount;
                unchecked {
                    ++h;
                }
            } else {
                break;
            }
        }
        win.head = h;

        uint256 activeCount = len - h;
        if (activeCount >= maxWindowTxCount) {
            revert RollingWindowTxCountExceeded(activeCount, maxWindowTxCount);
        }

        newActiveSpend = uint256(activeSum) + amount;
        if (newActiveSpend > cap) {
            uint64 oldestExpiry = h < len
                ? win.entries[h].timestamp + uint64(ROLLING_WINDOW_SECONDS)
                : uint64(nowTs + ROLLING_WINDOW_SECONDS);
            revert Rolling24hWindowCapExceeded(newActiveSpend, cap, oldestExpiry);
        }

        win.activeSum = uint192(newActiveSpend);
        win.entries.push(SpendEntry({timestamp: uint64(nowTs), amount: uint192(amount)}));
    }

    function _inspectWindow(RollingWindow storage win)
        private
        view
        returns (uint256 activeSpend, uint256 activeTxCount, uint64 nextExpiryTimestamp)
    {
        uint256 len = win.entries.length;
        uint64 h = win.head;
        uint256 sum = win.activeSum;
        uint256 nowTs = block.timestamp;

        while (h < len) {
            SpendEntry storage entry = win.entries[h];
            if (uint256(entry.timestamp) + ROLLING_WINDOW_SECONDS <= nowTs) {
                sum -= entry.amount;
                unchecked {
                    ++h;
                }
            } else {
                break;
            }
        }

        activeSpend = sum;
        activeTxCount = len - h;
        nextExpiryTimestamp = h < len ? win.entries[h].timestamp + uint64(ROLLING_WINDOW_SECONDS) : 0;
    }

    function _verifyMerkleProof(
        bytes32[] calldata proof,
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
