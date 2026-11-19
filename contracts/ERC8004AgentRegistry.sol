// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC8004Registry} from "./interfaces/IERC8004Registry.sol";

/// @title ERC8004AgentRegistry
/// @notice On-chain Trustless Agents Identity, Reputation, and Capability Verification Registry (ERC-8004 aligned).
///         Gates AI Agent x402 settlements on Arbitrum so MandateVault only releases capital to verified providers
///         whose live reputation basis points meet the human-signed AP2 Mandate threshold.
contract ERC8004AgentRegistry is IERC8004Registry {
    uint16 public constant MAX_BPS = 10_000;
    uint16 public constant REWARD_INCREMENT_BPS = 25;

    error UnauthorizedCaller();
    error InvalidReputationScore(uint16 provided);
    error ProviderAlreadyRegistered(address provider);
    error ProviderNotRegistered(address provider);

    address public owner;
    mapping(address => bool) public authorizedVaults;
    mapping(address => AgentIdentity) private _identities;
    mapping(address => mapping(bytes32 => bool)) private _capabilities;

    modifier onlyOwner() {
        if (msg.sender != owner) revert UnauthorizedCaller();
        _;
    }

    modifier onlyAuthorizedVaultOrOwner() {
        if (msg.sender != owner && !authorizedVaults[msg.sender]) revert UnauthorizedCaller();
        _;
    }

    constructor(address initialOwner) {
        owner = initialOwner == address(0) ? msg.sender : initialOwner;
    }

    function setAuthorizedVault(address vault, bool allowed) external onlyOwner {
        authorizedVaults[vault] = allowed;
    }

    function registerProvider(
        address provider,
        uint16 initialReputationBps,
        bytes32 capabilityRoot,
        bytes32[] calldata explicitCapabilities,
        string calldata metadataUri
    ) external onlyOwner {
        if (_identities[provider].registered) revert ProviderAlreadyRegistered(provider);
        if (initialReputationBps > MAX_BPS) revert InvalidReputationScore(initialReputationBps);

        _identities[provider] = AgentIdentity({
            registered: true,
            active: true,
            reputationBps: initialReputationBps,
            fulfilledOrders: 0,
            disputedOrders: 0,
            cumulativeVolumeUsdc: 0,
            capabilityRoot: capabilityRoot,
            metadataUri: metadataUri
        });

        for (uint256 i = 0; i < explicitCapabilities.length; ++i) {
            _capabilities[provider][explicitCapabilities[i]] = true;
        }

        emit ProviderRegistered(provider, initialReputationBps, capabilityRoot, metadataUri);
    }

    function setProviderStatus(address provider, bool active) external onlyOwner {
        if (!_identities[provider].registered) revert ProviderNotRegistered(provider);
        _identities[provider].active = active;
        emit ProviderStatusUpdated(provider, active);
    }

    function setProviderCapability(address provider, bytes32 capability, bool supported) external onlyOwner {
        if (!_identities[provider].registered) revert ProviderNotRegistered(provider);
        _capabilities[provider][capability] = supported;
    }

    function setProviderReputation(address provider, uint16 newReputationBps) external onlyOwner {
        if (!_identities[provider].registered) revert ProviderNotRegistered(provider);
        if (newReputationBps > MAX_BPS) revert InvalidReputationScore(newReputationBps);
        _identities[provider].reputationBps = newReputationBps;
    }

    /// @inheritdoc IERC8004Registry
    function checkProviderEligibility(
        address provider,
        uint16 minReputationBps,
        bytes32 requiredCapability
    ) external view override returns (bool eligible, uint16 actualReputationBps) {
        AgentIdentity storage id = _identities[provider];
        actualReputationBps = id.reputationBps;
        if (!id.registered || !id.active) {
            return (false, actualReputationBps);
        }
        if (actualReputationBps < minReputationBps) {
            return (false, actualReputationBps);
        }
        if (requiredCapability != bytes32(0)) {
            bool capMatch = _capabilities[provider][requiredCapability] || (id.capabilityRoot == requiredCapability);
            if (!capMatch) {
                return (false, actualReputationBps);
            }
        }
        return (true, actualReputationBps);
    }

    /// @inheritdoc IERC8004Registry
    function getAgentIdentity(address provider) external view override returns (AgentIdentity memory) {
        return _identities[provider];
    }

    /// @inheritdoc IERC8004Registry
    function recordSettlementSuccess(address provider, uint256 amountUsdc) external override onlyAuthorizedVaultOrOwner {
        AgentIdentity storage id = _identities[provider];
        if (!id.registered) revert ProviderNotRegistered(provider);

        unchecked {
            ++id.fulfilledOrders;
            id.cumulativeVolumeUsdc += amountUsdc;
        }
        uint16 updated = id.reputationBps + REWARD_INCREMENT_BPS;
        if (updated > MAX_BPS) {
            updated = MAX_BPS;
        }
        id.reputationBps = updated;
        emit FulfillmentRecorded(provider, msg.sender, amountUsdc, updated);
    }

    /// @inheritdoc IERC8004Registry
    function recordDisputePenalty(address provider, uint16 penaltyBps) external override onlyAuthorizedVaultOrOwner {
        AgentIdentity storage id = _identities[provider];
        if (!id.registered) revert ProviderNotRegistered(provider);

        unchecked {
            ++id.disputedOrders;
        }
        uint16 updated = id.reputationBps > penaltyBps ? id.reputationBps - penaltyBps : 0;
        id.reputationBps = updated;
        emit DisputeSlashRecorded(provider, msg.sender, penaltyBps, updated);
    }
}
