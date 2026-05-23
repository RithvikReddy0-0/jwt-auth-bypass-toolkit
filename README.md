# JWT Authentication Bypass & Algorithm Confusion Toolkit
### Hackathon Project — MITRE ATT&CK T1550.001


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

## Implemented Attack Functions & Modules

Our offensive toolkit (`attacker-toolkit/attack.py`) is fully automated and implements the following distinct red-team functions:

1. **`inspect` (Claim Enumeration):** Decodes JWT headers and payloads locally to inspect claims without needing the secret key.
2. **`none` (CVE-2015-9235 Exploit):** Automatically strips the JWT signature, alters the `alg` header to `none`, injects arbitrary payload claims, and bypasses authentication.
3. **`confusion` (CVE-2016-5431 Exploit):** Automates the RS256→HS256 downgrade. It fetches the server's public key, encodes it in Base64URL, signs a forged payload symmetrically, and achieves vertical privilege escalation.
4. **`fuzz` (Authorization Boundary Fuzzing):** Rapidly mutates JWT claims (`role`, `scope`, `tier`, `permissions`) to brute-force and map out the backend authorization logic.
5. **`tenants` (Horizontal Privilege Escalation):** Automatically modifies the `tenant` claim in an authenticated JWT to breach database boundaries and steal cross-tenant data.
6. **`audience` (Service-to-Service Abuse):** Modifies the `aud` (Audience) claim to test if the microservice strictly validates token destinations.
7. **`replay` (State/Time Attacks):** Tests if the server tracks `jti` (JWT ID) claims or enforces strict `exp` (Expiration) checks to prevent token replay attacks.

---

## Team Structure
| Person | Role | Files |
|---|---|---|
| **Mukkara Rithvik Reddy** | Vulnerable Cloud-Native API | `vulnerable-api/app.py`, `vulnerable-api/generate_keys.py`, `vulnerable-api/Dockerfile`, `validators/` |
| **Ravva Siddhartha** | Offensive Attack Toolkit | `attacker-toolkit/attack.py`, `attacker-toolkit/*.py` |
| **Aman Agarwal** | Demo Flow, Testing, Hardening | `docs/demo-flow.md`, `docs/hardening.md`, `tests/`, `demo screenshots` |
| **Kopperla Bharath Reddy** | Documentation, README, PPT, Final Report | `README.md`, `docs/architecture.md`, `docs/hardening.md`, `docs/demo-flow.md`, `presentation.pptx`, `final_report.docx` |

---

## Quick Start

We have provided a detailed, step-by-step setup guide for both Docker and Local Python environments.

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

To run these attacks, first get a token via the `/login` endpoint, then use the master CLI:

```bash
# 1. Enumerate Claims
python attack.py inspect $TOKEN

# 2. Fuzz Authorization Boundaries
python attack.py fuzz $TOKEN --target http://localhost:5001/admin/vulnerable

# 3. alg:none Bypass
python attack.py none $TOKEN --target http://localhost:5001/admin/vulnerable --set role=admin

# 4. RS256→HS256 Algorithm Confusion
python attack.py confusion --target http://localhost:5001 --endpoint http://localhost:5001/admin/vulnerable --set role=admin

# 5. Tenant Isolation Abuse
python attack.py tenants $TOKEN --target http://localhost:5001/tenant-data/vulnerable/companyB --tenant companyB

# 6. Token Replay Attack (Blocked by Secure Validator)
python attack.py replay $TOKEN --target http://localhost:5001/admin/vulnerable --count 5

# 7. Audience Confusion Attack (Blocked by Secure Validator)
python attack.py audience $TOKEN --target http://localhost:5001/admin/vulnerable
```

## Project Structure

```
jwt-auth-bypass-toolkit/
├── vulnerable-api/
│   ├── app.py              Flask API (Microservice Blueprint architecture)
│   ├── generate_keys.py    RSA key pair generator
│   ├── requirements.txt    Python dependencies
│   ├── Dockerfile          Container setup for vulnerable API
│   ├── validators/         Vulnerable vs Secure JWT implementations
│   └── keys/
│       ├── private.pem     RS256 signing key
│       └── public.pem      RS256 verification key
│
├── attacker-toolkit/
│   ├── attack.py           Master CLI tool
│   ├── claim_enum.py       Attack: Inspect and enumerate claims
│   ├── none_attack.py      Attack: alg:none bypass
│   ├── alg_confusion.py    Attack: RS256→HS256 confusion
│   ├── auth_fuzzer.py      Attack: Fuzz authorization boundaries
│   ├── tenant_abuse.py     Attack: Cross-tenant data breach
│   ├── audience_confusion.py Attack: Target downstream services
│   ├── replay.py           Attack: Token replay tests
│   ├── forge_claims.py     Manual JWT forging
│   ├── utils.py            Shared CLI formatting helpers
│   ├── advanced/           Edge case payloads
│   └── requirements.txt    Python dependencies
│
├── docs/
│   ├── setup_guide.md      Setup documentation (Docker/Local)
│   ├── threat_model.md     STRIDE Threat Model for Hackathon rubric
│   ├── demo-flow.md        Step-by-step presentation guide
│   ├── architecture.md     System diagrams
│   └── hardening.md        Security fixes + secure code examples
│
├── tests/
│   └── edge_cases/         Test generation tools
│
├── docker-compose.yml      Automated environment builder
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

### 3. Authorization Boundary Fuzzing

Fuzzing involves rapidly sending mutated JWT claims (like `role`, `scope`, or `permissions`) to brute-force the backend's authorization rules. Because we can bypass the cryptographic signature (via `alg:none` or Algorithm Confusion), we can systematically map out exactly which claims are required to access restricted endpoints.

### 4. Tenant Isolation Abuse

In cloud-native microservices, databases often rely on the `tenant` claim within the JWT to enforce Row Level Security (RLS) or data isolation (e.g., `tenant: companyA`). If the signature validation is bypassed, an attacker can simply alter their token to read `tenant: companyB`. The microservice will dutifully fetch the other company's data, resulting in a Horizontal Privilege Escalation and data breach.

### 5. Audience Confusion

The `aud` (Audience) claim specifies the intended recipient of a token. An attacker might legitimately acquire a token for a low-privilege service (like a frontend API). If a high-privilege internal microservice fails to validate that the `aud` claim matches its own identifier, the attacker can submit the low-privilege token to the high-privilege service to bypass authorization.

### 6. Token Replay

Stateless JWTs do not require a database lookup, making them fast but vulnerable to being captured and reused (replayed). Secure systems must track the `jti` (JWT ID) in a high-speed cache (like Redis) or enforce very strict `exp` (Expiration) times. If these protections are missing, an attacker can continually reuse a stolen token indefinitely.

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

### Step-by-Step Demo

Refer to [docs/attack_chain.md](docs/attack_chain.md) and [docs/demo-flow.md](docs/demo-flow.md) for the complete sequence of commands using the new `attack.py` master CLI tool.

🔥 **[View the Live Terminal Attack Outputs Here](docs/attack_outputs.md)**

---

## References

- [PortSwigger JWT Labs](https://portswigger.net/web-security/jwt)
- [RFC 7519 — JWT Specification](https://datatracker.ietf.org/doc/html/rfc7519)
- [CVE-2015-9235](https://nvd.nist.gov/vuln/detail/CVE-2015-9235) — alg:none
- [CVE-2016-5431](https://nvd.nist.gov/vuln/detail/CVE-2016-5431) — Algorithm confusion
- [MITRE ATT&CK T1550.001](https://attack.mitre.org/techniques/T1550/001/)
