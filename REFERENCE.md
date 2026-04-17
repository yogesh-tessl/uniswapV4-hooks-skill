# Uniswap v4 Hooks Reference

## Common Vulnerability Patterns

### 1. Overflow in Price Calculations
```solidity
// BAD: Can overflow
uint256 price = uint256(sqrtPriceX96) ** 2;

// GOOD: Use mulDiv
uint256 price = FullMath.mulDiv(uint256(sqrtPriceX96), uint256(sqrtPriceX96), 1 << 96);
```

### 2. Incorrect Fee Calculation
```solidity
// BAD: Simple addition is wrong
uint256 totalFee = protocolFee + lpFee;

// GOOD: Protocol fee taken first, then LP fee from remainder
// protocolFee + lpFee * (1_000_000 - protocolFee) / 1_000_000
```

### 3. Missing Timestamp Validation
```solidity
// BAD: No future check
function submitOrder(uint256 expiration) external {
    orders[msg.sender] = Order(expiration, ...);
}

// GOOD: Validate expiration is in future
function submitOrder(uint256 expiration) external {
    require(expiration > block.timestamp, "Expiration must be in future");
    require(expiration % interval == 0, "Must align to interval");
    orders[msg.sender] = Order(expiration, ...);
}
```

### 4. Trusting Sender Without Verification
```solidity
// BAD: sender could be malicious contract
address user = sender;

// GOOD: Verify router and query actual user
require(trustedRouters[sender], "Untrusted router");
address user = IMsgSender(sender).msgSender();
```

## Token Handling Hazards

**Unsupported token types** (document explicitly if your hook doesn't handle):
- **Fee-on-transfer**: Actual received amount differs from transfer amount
- **Rebasing**: Balance changes without transfers
- **ERC-777**: Reentrancy via transfer hooks
- **Pausable**: Transfers can revert unexpectedly
- **Blocklist**: Some addresses may be blocked

```solidity
// If handling non-standard tokens, validate actual balances
uint256 balanceBefore = token.balanceOf(address(this));
token.transferFrom(user, address(this), amount);
uint256 actualReceived = token.balanceOf(address(this)) - balanceBefore;
```

## Testing Requirements

Use Foundry for comprehensive testing:

```solidity
// Invariant test: Deltas always balance
function invariant_deltasBalance() public {
    assertEq(poolManager.currencyDelta(address(hook), currency0), 0);
    assertEq(poolManager.currencyDelta(address(hook), currency1), 0);
}

// Fuzz test: No overflow in price calculations
function testFuzz_priceCalculation(uint160 sqrtPriceX96) public {
    vm.assume(sqrtPriceX96 >= TickMath.MIN_SQRT_PRICE);
    vm.assume(sqrtPriceX96 <= TickMath.MAX_SQRT_PRICE);
    // Should not revert
    hook.calculatePrice(sqrtPriceX96);
}

// Test both swap directions
function test_swapZeroForOne() public { ... }
function test_swapOneForZero() public { ... }
```

## Risk Assessment (Self-Score)

Before deployment, score your hook (0-33 scale):

| Dimension | Score Range | Your Hook |
|-----------|-------------|-----------|
| Code Complexity | 0-5 | |
| Custom Math | 0-5 | |
| External Dependencies | 0-3 | |
| External Liquidity | 0-3 | |
| TVL Potential | 0-5 | |
| Team Maturity | 0-3 | |
| Upgradeability | 0-3 | |
| Autonomous Updates | 0-3 | |
| Price-Impacting | 0-3 | |

**Risk Tiers:**
- **Low (0-6)**: 1 audit + AI static analysis
- **Medium (7-17)**: 1-2 audits + bug bounty recommended
- **High (18-33)**: 2 audits (1 math specialist) + mandatory bug bounty + monitoring

## Production Hooks Reference

Allowlisted hooks on Uniswap (as of Jan 2025):
- Flaunch (meme coin launchpad, 100% fees to creators)
- EulerSwap (lending-powered DEX)
- Zaha Studios TWAMM (time-weighted orders)
- Coinbase Verified Pools
- Panoptic Oracle Hook
- AEGIS Dynamic Fee Mechanism

Study these for patterns: https://raw.githubusercontent.com/fewwwww/awesome-uniswap-hooks/refs/heads/main/README.md

## Resources

- **v4-core**: https://github.com/Uniswap/v4-core
- **v4-periphery**: https://github.com/Uniswap/v4-periphery
- **Security Framework**: https://docs.uniswap.org/contracts/v4/security
- **Hook Examples**: https://github.com/fewwwww/awesome-uniswap-hooks
- **Address Mining**: https://github.com/hensha256/hook-mine-and-sinker
- **v4 by Example**: https://v4-by-example.org
