# Tutorial: Running a Cryptographic Configuration Review

**Audience:** Security engineers and developers new to cryptologik
**Time:** ~20 minutes
**Prerequisites:** Python 3.11+, cryptologik installed

---

## Overview

In this tutorial you will:
1. Install cryptologik
2. Scan a sample code file for cryptographic anti-patterns
3. Interpret the findings
4. Run a key management posture check
5. Generate a report

The same workflow also supports Java, Go, and JavaScript/TypeScript sources, so once you are comfortable with the Python example below you can point the scanner at mixed-language repositories without changing the basic command shape.

---

## Step 1: Install cryptologik

```bash
git clone https://github.com/hiagokinlevi/cryptologik.git
cd cryptologik

python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

pip install -e .

cp .env.example .env
# Review .env — defaults are suitable for this tutorial

cryptologik --version
# Expected: cryptologik, version 1.0.0
```

---

## Step 2: Create a Sample File with Cryptographic Issues

For this tutorial, create a sample Python file with intentional cryptographic weaknesses:

```bash
cat > /tmp/insecure_crypto_sample.py << 'EOF'
import hashlib
import random
from Crypto.Cipher import DES, AES

def hash_password_wrong(password: str) -> str:
    # Wrong: MD5 is not suitable for password hashing
    return hashlib.md5(password.encode()).hexdigest()

def encrypt_data_ecb(key: bytes, data: bytes) -> bytes:
    # Wrong: ECB mode is not semantically secure
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)

def generate_api_key() -> str:
    # Wrong: random module is not cryptographically secure
    token = random.token_hex(32)
    return token

def legacy_encrypt(key: bytes, data: bytes) -> bytes:
    # Wrong: DES is deprecated and broken
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(data)
EOF
```

---

## Step 3: Run the Crypto Config Review

```bash
cryptologik review-crypto-config \
  --path /tmp/insecure_crypto_sample.py \
  --strictness standard \
  --output /tmp/findings.json
```

You should see a table with multiple findings. Let's interpret each one:

### Finding 1: MD5 Usage (High)
The scanner detected `MD5` in a security context. In this case, it's being used for password hashing — which is wrong. MD5 is not a password hashing function; it's a general-purpose hash that is trivially reversed with rainbow tables.

**What to do:** Replace `hashlib.md5()` for password storage with `argon2-cffi` or `bcrypt`.

### Finding 2: AES-ECB Mode (High)
The scanner detected `AES.MODE_ECB`. ECB mode encrypts each block of data independently, meaning identical plaintext blocks produce identical ciphertext blocks. For example, encrypting a solid-color image with ECB produces a recognizable pattern in the ciphertext.

**What to do:** Replace ECB with AES-GCM: `AES.new(key, AES.MODE_GCM)`.

### Finding 3: Non-Cryptographic PRNG (High)
The scanner detected `import random` followed by its use near a security-sensitive variable (`token`). The `random` module uses the Mersenne Twister, which is not cryptographically secure.

**What to do:** Replace `random.token_hex(32)` with `secrets.token_hex(32)`.

### Finding 4: DES Usage (Critical)
The scanner detected `DES`. DES uses a 56-bit key that can be brute-forced in hours with commodity hardware.

**What to do:** Remove all DES usage. Replace with AES-256-GCM.

If you want a quieter triage pass for CI, rerun the same command with `--strictness minimal`. That keeps the scan focused on high and critical findings while still using the same detection engine.

---

## Step 4: Review the JSON Output

```bash
python -m json.tool /tmp/findings.json
```

The JSON output is structured for downstream processing — you can import it into a SIEM, JIRA, or the `generate-report` command.

---

## Step 5: Key Management Posture Check

Create a sample key management config with issues:

```bash
cat > /tmp/sample-key-config.yaml << 'EOF'
keys:
  production_db_password:
    type: generic
    storage:
      location: plaintext_file
      path: /etc/myapp/secrets.conf

  api_key_external:
    type: api_key
    rotation:
      automated: false
      interval_days: 365
    storage:
      location: environment_variable
    access_control:
      allowed_principals:
        - "*"
EOF
```

```bash
cryptologik review-key-posture \
  --config /tmp/sample-key-config.yaml \
  --output /tmp/key-findings.json
```

Expected findings:
- `production_db_password`: No rotation policy + plaintext file storage (Critical)
- `api_key_external`: Manual rotation + 365-day interval (too long for API keys) + wildcard access (Critical)

---

## Step 6: Generate a Report

```bash
cryptologik generate-report \
  --findings-json /tmp/findings.json \
  --target "Sample insecure crypto application" \
  --verbosity standard \
  --output /tmp/crypto-review-report.md

# View the report
cat /tmp/crypto-review-report.md
```

---

## What's Next?

- Try the lab: `training/labs/lab_01_contract_review.md`
- Review the policy baseline: `policies/crypto-baselines/standard.yaml`
- Read the crypto security model: `docs/crypto-security-model.md`
- Explore the SWC reference: `blockchain/swc_mappings/swc_reference.yaml`
