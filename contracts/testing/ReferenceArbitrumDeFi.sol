// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "../interfaces/IERC20.sol";
import {IAaveV3Pool} from "../interfaces/IAaveV3Pool.sol";
import {IMandateVerifier} from "../interfaces/IMandateVerifier.sol";

/// @title ReferenceUSDC6
/// @notice Faithful 6-decimal ERC-20 token matching Arbitrum One Native USDC (`0xaf88d065e77c8cC2239327C5EDb3A432268e5831`)
///         for deterministic EVM execution and 10,000-iteration fuzz verification.
contract ReferenceUSDC6 is IERC20 {
    string public constant override name = "USD Coin";
    string public constant override symbol = "USDC";
    uint8 public constant override decimals = 6;

    uint256 public override totalSupply;
    mapping(address => uint256) public override balanceOf;
    mapping(address => mapping(address => uint256)) public override allowance;

    error InsufficientBalance(uint256 available, uint256 required);
    error InsufficientAllowance(uint256 available, uint256 required);

    function mint(address to, uint256 amount) external {
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function transfer(address to, uint256 value) external override returns (bool) {
        uint256 bal = balanceOf[msg.sender];
        if (bal < value) revert InsufficientBalance(bal, value);
        unchecked {
            balanceOf[msg.sender] = bal - value;
            balanceOf[to] += value;
        }
        emit Transfer(msg.sender, to, value);
        return true;
    }

    function approve(address spender, uint256 value) external override returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external override returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            if (allowed < value) revert InsufficientAllowance(allowed, value);
            unchecked {
                allowance[from][msg.sender] = allowed - value;
            }
        }
        uint256 bal = balanceOf[from];
        if (bal < value) revert InsufficientBalance(bal, value);
        unchecked {
            balanceOf[from] = bal - value;
            balanceOf[to] += value;
        }
        emit Transfer(from, to, value);
        return true;
    }
}

/// @title ReferenceAArbUSDCn
/// @notice Rebasing scaled-balance aToken mirroring Aave V3 `aArbUSDCn` (`0x724dc807b04555b71ed48a6896b6f41593b8c637`)
///         using exact WadRayMath (`1e27` RAY) half-up `rayMul` / `rayDiv` arithmetic.
contract ReferenceAArbUSDCn is IERC20 {
    uint256 internal constant RAY = 1e27;
    uint256 internal constant HALF_RAY = 0.5e27;

    string public constant override name = "Aave Arbitrum USDCn";
    string public constant override symbol = "aArbUSDCn";
    uint8 public constant override decimals = 6;

    address public immutable pool;
    uint256 public scaledTotalSupply;
    mapping(address => uint256) public scaledBalanceOf;
    mapping(address => mapping(address => uint256)) public override allowance;

    error OnlyPool();
    error BurnExceedsBalance(uint256 scaledAvailable, uint256 scaledRequired);

    constructor(address pool_) {
        pool = pool_;
    }

    modifier onlyPool() {
        if (msg.sender != pool) revert OnlyPool();
        _;
    }

    function _rayMul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0 || b == 0) return 0;
        return (a * b + HALF_RAY) / RAY;
    }

    function _rayDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        return (a * RAY + (b / 2)) / b;
    }

    function totalSupply() public view override returns (uint256) {
        uint256 index = ReferenceAaveV3Pool(pool).normalizedIncome();
        return _rayMul(scaledTotalSupply, index);
    }

    function balanceOf(address account) public view override returns (uint256) {
        uint256 index = ReferenceAaveV3Pool(pool).normalizedIncome();
        return _rayMul(scaledBalanceOf[account], index);
    }

    function mintScaled(address onBehalfOf, uint256 amount, uint256 index) external onlyPool returns (uint256 scaled) {
        scaled = _rayDiv(amount, index);
        scaledTotalSupply += scaled;
        scaledBalanceOf[onBehalfOf] += scaled;
        emit Transfer(address(0), onBehalfOf, amount);
    }

    function burnScaled(address from, uint256 amount, uint256 index) external onlyPool returns (uint256 scaled) {
        scaled = _rayDiv(amount, index);
        uint256 currentScaled = scaledBalanceOf[from];
        if (scaled > currentScaled) revert BurnExceedsBalance(currentScaled, scaled);
        unchecked {
            scaledBalanceOf[from] = currentScaled - scaled;
            scaledTotalSupply -= scaled;
        }
        emit Transfer(from, address(0), amount);
    }

    function transfer(address to, uint256 value) external override returns (bool) {
        uint256 index = ReferenceAaveV3Pool(pool).normalizedIncome();
        uint256 scaled = _rayDiv(value, index);
        uint256 currentScaled = scaledBalanceOf[msg.sender];
        if (scaled > currentScaled) revert BurnExceedsBalance(currentScaled, scaled);
        unchecked {
            scaledBalanceOf[msg.sender] = currentScaled - scaled;
            scaledBalanceOf[to] += scaled;
        }
        emit Transfer(msg.sender, to, value);
        return true;
    }

    function approve(address spender, uint256 value) external override returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external override returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            require(allowed >= value, "Allowance exceeded");
            allowance[from][msg.sender] = allowed - value;
        }
        uint256 index = ReferenceAaveV3Pool(pool).normalizedIncome();
        uint256 scaled = _rayDiv(value, index);
        uint256 currentScaled = scaledBalanceOf[from];
        if (scaled > currentScaled) revert BurnExceedsBalance(currentScaled, scaled);
        unchecked {
            scaledBalanceOf[from] = currentScaled - scaled;
            scaledBalanceOf[to] += scaled;
        }
        emit Transfer(from, to, value);
        return true;
    }
}

/// @title ReferenceAaveV3Pool
/// @notice Faithful Aave V3 Pool (`0x794a61358D6845594F94dc1DB02A252b5b4814aD`) reserve engine modeling continuous
///         RAY (`1e27`) liquidityIndex accrual over `block.timestamp` and backing liquidity solvencies.
contract ReferenceAaveV3Pool is IAaveV3Pool {
    uint256 internal constant RAY = 1e27;
    uint256 internal constant HALF_RAY = 0.5e27;
    uint256 internal constant SECONDS_PER_YEAR = 365 days;

    ReferenceUSDC6 public immutable underlyingUsdc;
    ReferenceAArbUSDCn public immutable aToken;

    uint128 public liquidityIndex;
    uint128 public currentLiquidityRate;
    uint40 public lastUpdateTimestamp;

    error UnsupportedReserve(address asset);

    constructor(address usdc_, uint128 initialIndexRay, uint128 initialLiquidityRateRay) {
        underlyingUsdc = ReferenceUSDC6(usdc_);
        aToken = new ReferenceAArbUSDCn(address(this));
        liquidityIndex = initialIndexRay == 0 ? uint128(RAY) : initialIndexRay;
        currentLiquidityRate = initialLiquidityRateRay;
        lastUpdateTimestamp = uint40(block.timestamp);
    }

    function setLiquidityRate(uint128 newRateRay) external {
        accrueReserve();
        currentLiquidityRate = newRateRay;
    }

    function normalizedIncome() public view returns (uint256) {
        uint256 dt = block.timestamp > lastUpdateTimestamp ? block.timestamp - lastUpdateTimestamp : 0;
        if (dt == 0 || currentLiquidityRate == 0) {
            return liquidityIndex;
        }
        uint256 linearInterest = RAY + (uint256(currentLiquidityRate) * dt) / SECONDS_PER_YEAR;
        return (uint256(liquidityIndex) * linearInterest + HALF_RAY) / RAY;
    }

    function accrueReserve() public returns (uint256 updatedIndex) {
        updatedIndex = normalizedIncome();
        uint256 prevSupply = aToken.totalSupply();
        liquidityIndex = uint128(updatedIndex);
        lastUpdateTimestamp = uint40(block.timestamp);

        // Ensure reserve holds enough underlying USDC to cover borrower-paid interest
        uint256 currentTotal = aToken.totalSupply();
        uint256 poolCash = underlyingUsdc.balanceOf(address(this));
        if (currentTotal > poolCash) {
            underlyingUsdc.mint(address(this), currentTotal - poolCash);
        }
        prevSupply;
    }

    function supply(address asset, uint256 amount, address onBehalfOf, uint16 /* referralCode */) external override {
        if (asset != address(underlyingUsdc)) revert UnsupportedReserve(asset);
        uint256 idx = accrueReserve();
        underlyingUsdc.transferFrom(msg.sender, address(this), amount);
        aToken.mintScaled(onBehalfOf, amount, idx);
    }

    function withdraw(address asset, uint256 amount, address to) external override returns (uint256 withdrawn) {
        if (asset != address(underlyingUsdc)) revert UnsupportedReserve(asset);
        uint256 idx = accrueReserve();
        uint256 userBalance = aToken.balanceOf(msg.sender);
        withdrawn = amount == type(uint256).max ? userBalance : amount;

        aToken.burnScaled(msg.sender, withdrawn, idx);

        uint256 poolCash = underlyingUsdc.balanceOf(address(this));
        if (poolCash < withdrawn) {
            underlyingUsdc.mint(address(this), withdrawn - poolCash);
        }
        underlyingUsdc.transfer(to, withdrawn);
    }

    function getReserveData(address asset) external view override returns (ReserveData memory data) {
        if (asset != address(underlyingUsdc)) revert UnsupportedReserve(asset);
        data.liquidityIndex = uint128(normalizedIncome());
        data.currentLiquidityRate = currentLiquidityRate;
        data.variableBorrowIndex = uint128(RAY);
        data.currentVariableBorrowRate = uint128((uint256(currentLiquidityRate) * 125) / 100);
        data.lastUpdateTimestamp = lastUpdateTimestamp;
        data.aTokenAddress = address(aToken);
    }
}
