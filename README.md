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
