// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IERC8004Registry
/// @notice Trustless Agents Identity, Reputation, and Capability Verification Registry interface (ERC-8004 aligned).
interface IERC8004Registry {
    struct AgentIdentity {
        bool registered;
        bool active;
        uint16 reputationBps;      // 0 - 10,000 basis points (10,000 = 100.00%)
        uint64 fulfilledOrders;
        uint64 disputedOrders;
        uint256 cumulativeVolumeUsdc;
        bytes32 capabilityRoot;    // Merkle root or single hash of supported AP2 capability tags
        string metadataUri;        // Agent / x402 service card URI
    }

    event ProviderRegistered(address indexed provider, uint16 initialReputationBps, bytes32 capabilityRoot, string metadataUri);
    event ProviderStatusUpdated(address indexed provider, bool active);
    event FulfillmentRecorded(address indexed provider, address indexed vault, uint256 amountUsdc, uint16 newReputationBps);
    event DisputeSlashRecorded(address indexed provider, address indexed vault, uint16 slashBps, uint16 newReputationBps);

    function checkProviderEligibility(
        address provider,
        uint16 minReputationBps,
        bytes32 requiredCapability
    ) external view returns (bool eligible, uint16 actualReputationBps);

    function getAgentIdentity(address provider) external view returns (AgentIdentity memory);

    function recordSettlementSuccess(address provider, uint256 amountUsdc) external;

    function recordDisputePenalty(address provider, uint16 penaltyBps) external;
}
