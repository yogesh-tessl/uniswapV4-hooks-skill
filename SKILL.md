---
name: uniswap-v4-hooks
description: "Generates, reviews, and audits Uniswap v4 hook contracts—validates permission flags, enforces delta accounting, implements secure callback patterns (access control, router verification, reentrancy guards), and produces Foundry test scaffolds. Activates when working with Uniswap v4 hooks, PoolManager, IHooks, BaseHook, beforeSwap, afterSwap, custom AMM logic, dynamic fees, or swap modifications. Use when creating, reviewing, or auditing hook contracts, or when the user says 'uniswap hooks' or invokes '/uniswap-v4-hooks'."
---

## Security Thinking

Before writing ANY hook code, assess the threat model:

**Who calls your hook?**
- Only `PoolManager` should call hook functions
- `msg.sender` in a hook is ALWAYS `PoolManager`, never the user
- The `sender` parameter is the router, not the end user

**What state is exposed?**
- Hooks execute mid-transaction—state can be manipulated between callbacks
- Reentrancy is possible through external calls
- Shared storage across pools using the same hook can break unexpectedly

**What can go wrong with deltas?**
- Every token in MUST equal tokens out (delta accounting)
- Rounding errors accumulate in iterative operations
- BeforeSwapDelta can bypass normal swap logic entirely

## CRITICAL: The NoOp Rug Pull Vector

Hooks with `BEFORE_SWAP_RETURNS_DELTA_FLAG` can **steal user funds**. This is the most dangerous hook permission.

```solidity
// MALICIOUS EXAMPLE - DO NOT USE
// This hook takes user tokens and returns nothing
function beforeSwap(...) external returns (bytes4, BeforeSwapDelta, uint24) {
    Currency input = params.zeroForOne ? key.currency0 : key.currency1;

    // Take all user funds
    input.take(poolManager, address(this), uint256(-params.amountSpecified), false);

    // Return delta saying we took everything, returning zero
    return (
        BaseHook.beforeSwap.selector,
        toBeforeSwapDelta(int128(-params.amountSpecified), 0), // THEFT
        0
    );
}
```

**When `beforeSwapReturnDelta: true`:**
- The hook can completely replace swap logic
- Pool math is SKIPPED if delta equals amountSpecified
- User funds flow to the hook, not through the AMM curve

**Defense:** NEVER enable `beforeSwapReturnDelta` unless implementing a legitimate custom AMM. Users should verify hook permissions before swapping.

## Permission Flags (Address Encoding)

Hook permissions are encoded in the contract address. The address must have specific bits set:

| Bit | Permission | Risk Level |
|-----|------------|------------|
| 0 | beforeInitialize | Low |
| 1 | afterInitialize | Low |
| 2 | beforeAddLiquidity | Medium |
| 3 | afterAddLiquidity | Medium |
| 4 | beforeRemoveLiquidity | Medium |
| 5 | afterRemoveLiquidity | Medium |
| 6 | beforeSwap | High |
| 7 | afterSwap | Medium |
| 8 | beforeDonate | Low |
| 9 | afterDonate | Low |
| 10 | beforeSwapReturnDelta | **CRITICAL** |
| 11 | afterSwapReturnDelta | High |
| 12 | afterAddLiquidityReturnDelta | Medium |
| 13 | afterRemoveLiquidityReturnDelta | Medium |

**Address Mining:** Use CREATE2 with salt grinding to deploy at an address with correct permission bits. Tools: `hook-mine-and-sinker`, `v4-hook-address-miner`.

## Access Control Pattern

```solidity
// REQUIRED: Verify caller is PoolManager
modifier onlyPoolManager() {
    require(msg.sender == address(poolManager), "Not PoolManager");
    _;
}

function beforeSwap(
    address sender,      // This is the ROUTER, not the user
    PoolKey calldata key,
    IPoolManager.SwapParams calldata params,
    bytes calldata hookData
) external onlyPoolManager returns (bytes4, BeforeSwapDelta, uint24) {
    // ...
}
```

## Identifying the Actual User (msg.sender Problem)

The `sender` parameter is the router contract, NOT the end user. To get the actual user:

```solidity
// 1. Define interface for trusted routers
interface IMsgSender {
    function msgSender() external view returns (address);
}

// 2. Maintain allowlist of trusted routers
mapping(address => bool) public trustedRouters;

// 3. Query router safely in hook
function afterSwap(
    address sender,  // This is the router
    PoolKey calldata key,
    IPoolManager.SwapParams calldata params,
    BalanceDelta delta,
    bytes calldata hookData
) external override returns (bytes4, int128) {
    // CRITICAL: Only trust verified routers
    if (!trustedRouters[sender]) {
        revert UntrustedRouter(sender);
    }

    // Safe to query actual user
    try IMsgSender(sender).msgSender() returns (address user) {
        // Use `user` for rewards, tracking, etc.
    } catch {
        revert RouterDoesNotImplementMsgSender();
    }

    return (this.afterSwap.selector, 0);
}
```

**NEVER trust `tx.origin`** for authentication (only acceptable for anti-gaming checks like self-referral prevention).

## Delta Accounting Rules

Deltas track what the hook owes or is owed. They MUST net to zero.

```solidity
// Taking tokens FROM PoolManager (hook receives tokens)
currency.take(poolManager, address(this), amount, false);

// Settling tokens TO PoolManager (hook sends tokens)
currency.settle(poolManager, address(this), amount, false);

// INVARIANT: All deltas must balance before unlock completes
```

**Common Delta Bugs:**
- Forgetting to settle after taking
- Rounding in wrong direction (always round against the user/hook)
- Not handling both swap directions (zeroForOne true AND false)

## Hook Development Workflow

Follow this sequence with validation gates between each step:

1. **Define minimal permissions** — List only the hook callbacks your logic requires in `getHookPermissions()`. Verify no `ReturnDelta` flags are set unless implementing a custom AMM.
2. **Implement from template** — Start from the Base Hook Template below. Add `onlyPoolManager` modifier to every hook function. Never use `unchecked` blocks for price/amount math.
3. **Mine deployment address** — Use CREATE2 salt grinding (`hook-mine-and-sinker` or `v4-hook-address-miner`). **Gate:** verify mined address permission bits match `getHookPermissions()` exactly before proceeding.
4. **Validate delta accounting** — Confirm every `take` has a matching `settle`. Test both `zeroForOne` directions. **Gate:** run invariant test asserting all currency deltas are zero after each operation.
5. **Run Foundry test suite** — Fuzz price calculations, test both swap directions, exercise all callback paths. See [REFERENCE.md](REFERENCE.md) for test examples. **Gate:** all tests green, no overflow warnings.
6. **Pre-deployment audit** — Walk through the Audit Checklist below. Score your hook using the risk assessment in REFERENCE.md to determine audit depth.

## Base Hook Template

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {BaseHook} from "v4-periphery/src/base/hooks/BaseHook.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {BalanceDelta} from "v4-core/types/BalanceDelta.sol";
import {Hooks} from "v4-core/libraries/Hooks.sol";

contract MyHook is BaseHook {
    constructor(IPoolManager _manager) BaseHook(_manager) {}

    function getHookPermissions() public pure override returns (Hooks.Permissions memory) {
        return Hooks.Permissions({
            beforeInitialize: false,
            afterInitialize: false,
            beforeAddLiquidity: false,
            afterAddLiquidity: false,
            beforeRemoveLiquidity: false,
            afterRemoveLiquidity: false,
            beforeSwap: false,
            afterSwap: true,  // Enable only what you need
            beforeDonate: false,
            afterDonate: false,
            beforeSwapReturnDelta: false,  // DANGEROUS - enable with caution
            afterSwapReturnDelta: false,
            afterAddLiquidityReturnDelta: false,
            afterRemoveLiquidityReturnDelta: false
        });
    }

    function _afterSwap(
        address sender,
        PoolKey calldata key,
        IPoolManager.SwapParams calldata params,
        BalanceDelta delta,
        bytes calldata hookData
    ) internal override returns (bytes4, int128) {
        // Your logic here
        return (this.afterSwap.selector, 0);
    }
}
```

## Vulnerability Patterns, Testing & Reference

See [REFERENCE.md](REFERENCE.md) for common vulnerability patterns (overflow, fee calculation, timestamp, sender verification), token handling hazards, Foundry testing examples, risk assessment scoring, production hooks reference, and external resources.

## Audit Checklist (Pre-Deployment)

- [ ] All hook functions check `msg.sender == poolManager`
- [ ] Deltas verified to net zero in all paths
- [ ] No overflow possible in math operations (use `mulDiv`, no `unchecked`)
- [ ] Router allowlist implemented if identifying users
- [ ] Token types explicitly documented
- [ ] Reentrancy guards on external calls
- [ ] Timestamp validations in place
- [ ] Permission flags minimal and match mined address bits
- [ ] No sensitive state readable mid-swap by external contracts
- [ ] Fuzz tests pass for edge cases
- [ ] Invariant tests for delta accounting
- [ ] Both swap directions tested
- [ ] Fee calculations match Uniswap's formula
