# Lab 01: Smart Contract Security Review

**Difficulty:** Beginner–Intermediate
**Time:** 45–60 minutes
**Prerequisites:** Complete `training/tutorials/crypto-config-review.md`

---

## Scenario

You have been asked to review a simplified token contract before it is deployed to Ethereum mainnet. The contract implements an ERC-20-like token with a few custom features.

Your task is to identify security vulnerabilities using cryptologik's checklist and manual review.

---

## Lab Setup

Create the sample contract file:

```bash
mkdir -p /tmp/contracts
cat > /tmp/contracts/VulnerableToken.sol << 'EOF'
// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

contract VulnerableToken {
    mapping(address => uint256) public balances;
    address public owner;
    uint256 public totalSupply;

    constructor(uint256 _initialSupply) {
        owner = msg.sender;
        totalSupply = _initialSupply;
        balances[msg.sender] = _initialSupply;
    }

    // Vulnerability: Authorization via tx.origin (SWC-115)
    modifier onlyOwner() {
        require(tx.origin == owner, "Not owner");
        _;
    }

    // Vulnerability: Unprotected withdraw (SWC-105)
    function withdraw() public {
        payable(msg.sender).transfer(address(this).balance);
    }

    // Vulnerability: Integer overflow risk (Solidity 0.7 — SWC-101)
    function mint(address to, uint256 amount) public onlyOwner {
        balances[to] += amount;
        totalSupply += amount;
    }

    // Vulnerability: Reentrancy risk (SWC-107)
    function withdrawUserBalance(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        // External call BEFORE state update — classic reentrancy setup
        payable(msg.sender).call{value: amount}("");
        balances[msg.sender] -= amount;
    }

    // Vulnerability: Weak randomness (SWC-120)
    function randomReward(address user) public {
        uint256 reward = uint256(block.timestamp) % 100;
        balances[user] += reward;
    }

    function transfer(address to, uint256 amount) public returns (bool) {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        balances[to] += amount;
        return true;
    }

    receive() external payable {}
}
EOF
```

---

## Exercise 1: Run Automated Checklist (10 min)

```bash
cryptologik review-contract-checklist \
  --contract /tmp/contracts/VulnerableToken.sol \
  --output /tmp/contract-findings.json
```

Review the output. Answer the following questions:

1. How many checklist items were triggered?
2. Which SWC IDs were flagged?
3. Which finding has the highest risk level?
4. Are there any findings in the contract that the automated tool did NOT flag? (Hint: look at the `withdraw()` function carefully)

---

## Exercise 2: Manual Reentrancy Analysis (15 min)

Examine the `withdrawUserBalance` function carefully:

```solidity
function withdrawUserBalance(uint256 amount) public {
    require(balances[msg.sender] >= amount, "Insufficient balance");
    payable(msg.sender).call{value: amount}("");  // External call
    balances[msg.sender] -= amount;               // State update AFTER call
}
```

**Questions:**
1. What pattern does this violate? (Hint: checks-effects-interactions)
2. How could an attacker exploit this?
3. What would a malicious contract's `receive()` function look like in an attack?
4. How would you fix this function?

**Write the fixed version of `withdrawUserBalance`:**

```solidity
// Your fix here:
function withdrawUserBalance(uint256 amount) public {
    require(balances[msg.sender] >= amount, "Insufficient balance");
    // TODO: Move state update before external call
    // TODO: Consider adding ReentrancyGuard
}
```

---

## Exercise 3: Access Control Analysis (10 min)

Examine the `onlyOwner` modifier:

```solidity
modifier onlyOwner() {
    require(tx.origin == owner, "Not owner");
    _;
}
```

**Questions:**
1. Why is `tx.origin` dangerous for authorization? (See SWC-115)
2. Construct a scenario: how could an attacker exploit a contract that uses `tx.origin` for authorization?
3. What should replace `tx.origin`?

---

## Exercise 4: Integer Overflow Assessment (10 min)

The contract uses `pragma solidity ^0.7.6`.

**Questions:**
1. Why is this a concern for the `mint` function?
2. If `balances[to]` is currently `type(uint256).max` and `mint` is called with `amount = 1`, what happens?
3. What two approaches would prevent this? (Solidity version upgrade vs. library approach)

---

## Exercise 5: Randomness Analysis (5 min)

Examine `randomReward`:

```solidity
function randomReward(address user) public {
    uint256 reward = uint256(block.timestamp) % 100;
    balances[user] += reward;
}
```

**Questions:**
1. Why is `block.timestamp` not a safe source of randomness on-chain?
2. In what scenarios would an attacker be able to manipulate or predict this value?
3. What is the correct approach for on-chain randomness?

---

## Exercise 6: Compile Your Findings (10 min)

Based on your analysis, create a findings table:

| # | SWC | Function | Risk | Finding | Fix |
|---|---|---|---|---|---|
| 1 | SWC-107 | withdrawUserBalance | Critical | | |
| 2 | SWC-115 | onlyOwner | High | | |
| 3 | SWC-105 | withdraw | Critical | | |
| 4 | SWC-101 | mint | High | | |
| 5 | SWC-120 | randomReward | High | | |

---

## Answer Key

### Exercise 2 — Reentrancy Fix

```solidity
function withdrawUserBalance(uint256 amount) public nonReentrant {
    require(balances[msg.sender] >= amount, "Insufficient balance");
    balances[msg.sender] -= amount;  // Effects BEFORE interactions
    payable(msg.sender).call{value: amount}("");
}
```

Or using pull payment pattern:
```solidity
mapping(address => uint256) public pendingWithdrawals;

function withdrawUserBalance(uint256 amount) public {
    require(balances[msg.sender] >= amount, "Insufficient balance");
    balances[msg.sender] -= amount;
    pendingWithdrawals[msg.sender] += amount;
}

function pullPayment() public nonReentrant {
    uint256 amount = pendingWithdrawals[msg.sender];
    pendingWithdrawals[msg.sender] = 0;
    payable(msg.sender).transfer(amount);
}
```

### Exercise 3 — tx.origin Fix

```solidity
modifier onlyOwner() {
    require(msg.sender == owner, "Not owner");
    _;
}
```

### Exercise 4 — Integer Overflow Fix

Option A: Upgrade to Solidity 0.8+
```solidity
pragma solidity ^0.8.20;
// Overflow is automatic — no SafeMath needed
```

Option B: Use SafeMath (for 0.7)
```solidity
using SafeMath for uint256;
balances[to] = balances[to].add(amount);
totalSupply = totalSupply.add(amount);
```

---

## Lab Complete

You have identified 5 vulnerabilities covering 5 different SWC entries in a single small contract. In real-world audits, contracts are much larger — systematic review using checklists like this one helps ensure coverage.

Proceed to `docs/smart-contract-review-guides/review-process.md` for the complete professional review process.
