// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IAaveV3Pool
/// @notice Minimal ABI-exact interface for Arbitrum One Official Aave V3 Pool (0x794a61358D6845594F94dc1DB02A252b5b4814aD).
interface IAaveV3Pool {
    struct ReserveConfigurationMap {
        uint256 data;
    }

    struct ReserveData {
        ReserveConfigurationMap configuration;
        uint128 liquidityIndex;
        uint128 currentLiquidityRate;
        uint128 variableBorrowIndex;
        uint128 currentVariableBorrowRate;
        uint128 currentStableBorrowRate;
        uint40 lastUpdateTimestamp;
        uint16 id;
        address aTokenAddress;
        address stableDebtTokenAddress;
        address variableDebtTokenAddress;
        address interestRateStrategyAddress;
        uint128 accruedToTreasury;
        uint128 unbacked;
        uint128 isolationModeTotalDebt;
    }

    /// @notice Supplies an `amount` of underlying asset into the reserve, receiving overlaid aTokens (e.g., aArbUSDCn).
    function supply(address asset, uint256 amount, address onBehalfOf, uint16 referralCode) external;

    /// @notice Withdraws an `amount` of underlying asset from the reserve, burning the equivalent aTokens owned.
    function withdraw(address asset, uint256 amount, address to) external returns (uint256);

    /// @notice Returns the state and configuration of the reserve on Arbitrum One.
    function getReserveData(address asset) external view returns (ReserveData memory);
}
