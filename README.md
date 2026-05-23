# JWT Authentication Bypass & Algorithm Confusion Toolkit
### Hackathon Project — MITRE ATT&CK T1550.001

> ⚠️ **Educational / CTF Use Only** — Do not deploy the vulnerable API in any production or internet-accessible environment.

---

## Hackathon Judging Criteria Guide

This repository has been structured to meet the maximum rubric scoring:
- **Code Quality & Engineering**: See `vulnerable-api/validators/vulnerable_validator.py` for heavily commented, intentional flaws vs secure implementations.
- **Attack/Defense Validity**: Fully functional [Automated Offensive Toolkit](attacker-toolkit/attack.py) targeting a multi-container microservice API.
- **Documentation (2 Marks)**: 
  - **Setup**: Detailed instructions in [docs/setup_guide.md](docs/setup_guide.md).
  - **Threat Model**: Complete analysis in [docs/threat_model.md](docs/threat_model.md).
  - **Code Comments**: Every vulnerability and defensive mechanism is annotated in the source code.

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

## Quick Start

We have provided a detailed, step-by-step setup guide for both Docker and Local Python environments.

👉 **[Read the Setup Documentation Here](docs/setup_guide.md)**

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
