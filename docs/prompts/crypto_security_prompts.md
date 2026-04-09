# Cryptographic and Blockchain Security — Review Prompts

Structured question sets for analysts conducting cryptographic and smart contract security reviews.

---

## Cryptographic Configuration Review Prompts

### Algorithm Selection
- What symmetric encryption algorithm and mode is in use? Is it approved per the baseline policy?
- What asymmetric algorithm and key size is in use? Does the key size meet the minimum for the intended security lifetime?
- What hash function is in use, and for what purpose? Is MD5 or SHA-1 used in a security context?
- What key derivation function is used for passwords? Is a memory-hard KDF (Argon2id, bcrypt, scrypt) in use?

### Implementation
- Is the IV/nonce generated randomly for each encryption operation? Or is it static/hardcoded?
- Is authenticated encryption (AEAD) in use? Or is encryption and MAC applied separately? (If separate, is it encrypt-then-MAC?)
- Where does randomness come from? Is it a CSPRNG, or a non-cryptographic PRNG?
- Are there any custom cryptographic implementations? (If yes: high risk — why was a standard library not used?)

### Key Management
- Where are cryptographic keys stored? (HSM, secrets manager, environment variable, plaintext file, code)
- What is the key rotation policy? When was each key last rotated?
- Who can access each key? Is access scoped to minimum required principals?
- What happens when a key holder leaves the organization?

---

## TLS Configuration Review Prompts

- What TLS version is in use? Is TLS 1.0 or 1.1 still enabled?
- What cipher suites are enabled? Are RC4, NULL, or EXPORT suites enabled?
- Is forward secrecy provided? (ECDHE or DHE key exchange)
- Are certificates from a trusted CA? Are they valid and not expiring soon?
- Is HSTS (HTTP Strict Transport Security) enabled with a sufficient max-age?
- Is certificate pinning in use where appropriate?

---

## Smart Contract Review Prompts

### Reentrancy
- Does this function make an external call?
- Does it follow checks-effects-interactions? (Check conditions → update state → external call)
- If state is updated after an external call: can the called contract re-enter and manipulate state?

### Access Control
- Who can call this function? Is that intentional?
- Is authorization via `msg.sender` (not `tx.origin`)?
- If this is a privileged function (owner, admin, minter), is it protected by an explicit modifier?
- Can any pathway bypass the access control check?

### Arithmetic
- What Solidity version is in use? If < 0.8, is SafeMath used?
- Are there any unchecked arithmetic blocks? What is the justification?
- Can any arithmetic operation produce unexpected results at boundary values?

### Randomness
- Is block.timestamp, blockhash, or block.difficulty used for randomness?
- Is there a Chainlink VRF or commit-reveal scheme in use?
- Can a validator/miner manipulate the outcome of any randomness-dependent function?

### Economic Attacks
- Can the state of this contract be manipulated within a single transaction via a flash loan?
- Are prices or balances read from external contracts? Can those be manipulated?
- Is this contract's governance subject to flash loan voting attacks?

---

## Key Management Review Prompts

### Rotation
- Is there a documented rotation policy for every key type?
- Is rotation automated or manual? What is the last rotation date for each key?
- Is there a process to trigger emergency rotation when a key is suspected compromised?

### Storage
- Is any key material stored in plaintext (files, env vars, code)?
- Is key material accessible to processes that don't need it?
- Has key material ever appeared in logs, error messages, or audit trails?

### Access
- Can any key be used by more principals than necessary?
- When an employee leaves, is their key access revoked?
- Is key access logged? Can you audit who used a key and when?

### Lifecycle
- Is there a complete inventory of all cryptographic keys?
- Are old, unused keys decommissioned or are they accumulated indefinitely?
- Is there a documented process for key generation, rotation, and destruction?
