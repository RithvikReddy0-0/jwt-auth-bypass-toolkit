# JWT Authentication Bypass & Algorithm Confusion Toolkit
### Hackathon Project — MITRE ATT&CK T1550.001

> ⚠️ **Educational / CTF Use Only** — Do not deploy the vulnerable API in any production or internet-accessible environment.

---

## Hackathon Judging Criteria Guide

This repository has been structured to meet the maximum rubric scoring. **Everything you need is in this single README document.**
- **Code Quality & Engineering**: See `vulnerable-api/validators/vulnerable_validator.py` for heavily commented, intentional flaws vs secure implementations.
- **Attack/Defense Validity**: Fully functional [Automated Offensive Toolkit](attacker-toolkit/attack.py) targeting a multi-container microservice API.
- **Documentation (2 Marks)**: 
  - **Setup Documentation**: See the detailed Setup section below.
  - **Threat Model**: See the formal Threat Model section below.
  - **Code Comments**: Every vulnerability and defensive mechanism is annotated in the source code.

---

## Threat Model

### System Overview
The architecture simulates a modern Cloud-Native microservices environment. Authentication is handled centrally by an Auth Gateway, which issues stateless JSON Web Tokens (JWTs). Downstream microservices (Admin, Billing, Tenant Data) do not contact a central database for authorization; instead, they completely trust the claims embedded within the cryptographically signed JWT.

### Trust Boundaries
1. **External Untrusted Zone:** The internet/user domain. Users can intercept, read, and manipulate their own JWTs.
2. **API Gateway Boundary:** The Auth service that validates initial credentials and generates the JWT.
3. **Internal Microservice Boundary:** The backend APIs that consume the JWT. They inherently trust the API Gateway. The vulnerability exists exactly at this boundary line—if the cryptographic verification is bypassed, the entire internal trust model collapses.

### STRIDE Threat Analysis

#### 1. Spoofing (Identity Forgery)
- **Threat:** An attacker alters the `sub` (subject) or `role` claims in the JWT payload to masquerade as an administrator.
- **Vulnerability:** CVE-2015-9235 (alg:none) allows an attacker to strip the signature and force the server to accept the forged identity without any cryptographic validation.
- **Impact:** Complete system compromise. 
- **Mitigation:** Strict Algorithm Pinning. The backend must hardcode `algorithms=["RS256"]` and ignore the user-provided `alg` header.

#### 2. Tampering (Signature Manipulation)
- **Threat:** An attacker alters the payload to modify scopes and re-signs the token.
- **Vulnerability:** CVE-2016-5431 (Algorithm Confusion). An attacker forces the backend to evaluate an asymmetric signature (RS256) symmetrically (HS256) using the publicly available RSA Public Key as the HMAC secret.
- **Impact:** Vertical Privilege Escalation. The attacker mathematically proves authenticity using the server's own public key against it.
- **Mitigation:** Enforcing strong, explicit key validation mappings. In Python's `jwt` library, passing an RSA public key to an HS256 algorithm securely throws an `InvalidKeyError` in modern versions.

#### 3. Information Disclosure (Cross-Tenant Breach)
- **Threat:** A user belonging to `companyA` modifies the `tenant` claim in their JWT to read data belonging to `companyB`.
- **Vulnerability:** Weak authorization boundary combined with cryptographic bypass.
- **Impact:** Horizontal Privilege Escalation resulting in a multi-tenant data breach.
- **Mitigation:** Enforcing strict cryptographic checks (stopping the forgery) combined with defense-in-depth database-level Row Level Security (RLS) linked to the authenticated session context.

#### 4. Elevation of Privilege (Audience Abuse)
- **Threat:** A token generated for a low-privilege `frontend-service` is captured and submitted to a high-privilege `internal-api`.
- **Vulnerability:** Missing Audience (`aud`) validation.
- **Impact:** Cross-service authorization bypass.
- **Mitigation:** The microservice must explicitly validate the `aud` claim during decoding to ensure the token was generated specifically for its use.

### Systemic Risks in Stateless Authentication
The fundamental flaw demonstrated in this project is **Trusting User Input for Cryptographic Control Paths**. 
By allowing the attacker to specify *how* the token should be validated (via the `alg` header), the server surrenders its security posture to the client. This violates the core principle of Zero Trust architecture, where security mechanisms must be centrally dictated and enforced regardless of client input.

---

## What This Is

A fully working demonstration of real-world JWT authentication vulnerabilities:

| # | Attack | MITRE ATT&CK | Impact |
|---|---|---|---|
| 1 | **alg:none bypass** | T1550.001 | Skip signature verification entirely |
| 2 | **RS256→HS256 confusion** | T1550.001 | Forge tokens with public key as secret |
| 3 | **Tenant Isolation Abuse** | T1090 | Cross-tenant data breach in microservices |
| 4 | **Audience Confusion** | T1190 | Cross-service authorization bypass |
| 5 | **Token Replay** | T1550.001 | Bypassing stateless architectures |

Capturing the flags from the vulnerable microservices demonstrates complete systemic compromise.

---

## Team Structure

| Person | Role | Files |
|---|---|---|
| **Person 1** | Vulnerable Cloud-Native API | `vulnerable-api/app.py`, `validators/` |
| **Person 2** | Offensive Attack Toolkit | `attacker-toolkit/attack.py`, `attacker-toolkit/*.py` |
| **Person 3** | Demo Flow, Hardening, Docs | `docs/*.md`, `README.md` |

---

## Setup Documentation

This guide provides detailed instructions on how to set up the Vulnerable JWT API and the Attacker Toolkit. You can choose between running everything locally using Python or running it in an isolated Docker environment.

### 🐳 Option A: Docker (Recommended)

The easiest way to run the project is using Docker Compose. This automatically spins up the API on port 5001 and sets up an isolated attacker container with all dependencies installed.

#### 1. Build and Start the Environment
Navigate to the root directory of the project and run:
```bash
docker compose up -d --build
```

#### 2. Verify the API is Running
Wait a few seconds, then verify the API is running by hitting the root endpoint:
```bash
curl http://localhost:5001/
```

#### 3. Run the Attacker Toolkit
You can execute commands inside the `attacker` container.
```bash
# Log in to get a token
TOKEN=$(curl -s -X POST http://localhost:5001/login -H "Content-Type: application/json" -d '{"username":"alice","password":"password123"}' | jq -r .token)

# Run the 'none' attack
docker compose exec attacker python attack.py none $TOKEN --target http://api:5001/admin/vulnerable --set role=admin

# Run the 'confusion' attack
docker compose exec attacker python attack.py confusion --target http://api:5001 --endpoint http://api:5001/admin/vulnerable --set role=admin
```

#### 4. Stop the Environment
```bash
docker compose down
```

---

### 🐍 Option B: Local Python

If you prefer to run the API directly on your host machine, follow these steps.

#### 1. Setup the Vulnerable API

First, generate the RSA keys required for the `RS256` asymmetric cryptography and start the server.

```bash
cd vulnerable-api
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python generate_keys.py
python app.py
```
*(Leave this terminal window open)*

#### 2. Setup the Attacker Toolkit

Open a **new terminal window** and navigate to the toolkit folder.

```bash
cd attacker-toolkit
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

#### 3. Execute Attacks

Now you can use the master CLI to launch attacks against your local API.

```bash
# Log in as a normal user to get a base token
TOKEN=$(curl -s -X POST http://localhost:5001/login -H "Content-Type: application/json" -d '{"username":"alice","password":"password123"}' | jq -r .token)

# Enumerate Claims
python attack.py inspect $TOKEN

# Attack 1: alg:none Bypass
python attack.py none $TOKEN --target http://localhost:5001/admin/vulnerable --set role=admin

# Attack 2: RS256→HS256 Algorithm Confusion
python attack.py confusion --target http://localhost:5001 --endpoint http://localhost:5001/admin/vulnerable --set role=admin

# Attack 3: Tenant Isolation Abuse
python attack.py tenants $TOKEN --target http://localhost:5001/tenant-data/vulnerable/companyB --tenant companyB
```

---

## API Endpoints

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/` | None | API microservices info |
| POST | `/login` | None | Get JWT token from Auth Gateway |
| GET | `/admin/vulnerable` | JWT (admin) | 🚩 Admin service (vulnerable validator) |
| GET | `/admin/secure` | JWT (admin) | 🔒 Admin service (secure validator) |
| GET | `/tenant-data/vulnerable/<id>`| JWT | 🚩 Tenant isolation test |
| GET | `/billing/vulnerable` | JWT | 🚩 Cross-service scope test |
| GET | `/internal/vulnerable` | JWT | 🚩 Internal-only flag |
| GET | `/public-key` | None | RSA public key |

### Login

```bash
curl -X POST http://localhost:5001/login \
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

### Step-by-Step Demo

Refer to [docs/attack_chain.md](docs/attack_chain.md) and [docs/demo-flow.md](docs/demo-flow.md) for the complete sequence of commands using the new `attack.py` master CLI tool.

---

## Project Structure

```
jwt-auth-bypass-toolkit/
├── vulnerable-api/
│   ├── app.py              Flask API (Microservice Blueprint architecture)
│   ├── generate_keys.py    RSA key pair generator
│   ├── requirements.txt
│   ├── Dockerfile
│   ├── validators/         Vulnerable vs Secure JWT implementations
│   └── keys/
│       ├── private.pem     RS256 signing key
│       └── public.pem      RS256 verification key
│
├── attacker-toolkit/
│   ├── attack.py           Master CLI tool
│   ├── none_attack.py      Attack: alg:none bypass
│   ├── alg_confusion.py    Attack: RS256→HS256 confusion
│   ├── auth_fuzzer.py      Attack: Fuzz authorization boundaries
│   ├── tenant_abuse.py     Attack: Cross-tenant data breach
│   ├── audience_confusion.py Attack: Target downstream services
│   ├── replay.py           Attack: Token replay tests
│   ├── forge_claims.py     Manual JWT forging
│   ├── utils.py            Shared helpers
│   ├── advanced/           Edge case and future attacks
│   └── requirements.txt
│
├── docs/
│   ├── attack_chain.md     Red team demo walkthrough
│   ├── mitre_mapping.md    MITRE ATT&CK framework mapping
│   ├── cloud_native_failures.md Why JWTs fail in distributed architectures
│   ├── hardening.md        Security fixes + secure code examples
│   ├── demo-flow.md        Step-by-step Postman guide
│   ├── architecture.md     System diagrams
│   └── future_scope.md     Advanced attacks (JKU, JWK, KID)
│
├── tests/
│   └── edge_cases/         Test generation tools
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
