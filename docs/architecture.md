# Architecture Documentation
## Person 3 — Demo + Security Hardening

---

## System Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                     JWT Auth Bypass Toolkit                         │
│                                                                     │
│  ┌────────────────────┐         ┌──────────────────────────────┐   │
│  │   Attacker         │         │   Vulnerable API             │   │
│  │   Toolkit          │ ──────► │   (Flask / Python)           │   │
│  │                    │         │                              │   │
│  │  none_attack.py    │         │  POST /login                 │   │
│  │  alg_confusion.py  │         │  GET  /profile               │   │
│  │  forge_claims.py   │         │  GET  /admin  ← TARGET       │   │
│  │  utils.py          │         │  GET  /public-key            │   │
│  └────────────────────┘         └──────────────────────────────┘   │
│                                          │                          │
│                                          │ signs with               │
│                                          ▼                          │
│                                 ┌────────────────┐                 │
│                                 │  RSA Key Pair  │                 │
│                                 │  private.pem   │                 │
│                                 │  public.pem    │                 │
│                                 └────────────────┘                 │
└─────────────────────────────────────────────────────────────────────┘
```

---

## JWT Token Flow (Normal)

```
Client              /login endpoint            JWT Library
  │                      │                         │
  │  POST /login          │                         │
  │  {user, pass, alg}   │                         │
  │─────────────────────►│                         │
  │                      │                         │
  │                      │  jwt.encode(payload,    │
  │                      │    private_key, RS256)  │
  │                      │────────────────────────►│
  │                      │◄────────────────────────│
  │                      │  JWT token              │
  │◄─────────────────────│                         │
  │  {token: "eyJ..."}   │                         │
  │                      │                         │
  │  GET /admin          │                         │
  │  Authorization: Bearer eyJ...                  │
  │─────────────────────►│                         │
  │                      │  jwt.decode(token,      │
  │                      │    public_key, RS256)   │
  │                      │────────────────────────►│
  │                      │◄────────────────────────│
  │                      │  {role: "user"}         │
  │                      │                         │
  │                      │  role != "admin" → 403  │
  │◄─────────────────────│                         │
  │  403 Forbidden       │                         │
```

---

## Attack 1: alg:none Flow

```
Attacker              /login           /admin (vulnerable)
  │                     │                    │
  │  Login as alice     │                    │
  │────────────────────►│                    │
  │◄────────────────────│                    │
  │  {token, role:user} │                    │
  │                     │                    │
  │  Decode token (no sig check)             │
  │  Modify: role=admin                      │
  │  Set: alg=none                           │
  │  Strip signature → eyJ...eyJ....         │
  │                                          │
  │  GET /admin                              │
  │  Authorization: Bearer eyJ...eyJ....    │
  │─────────────────────────────────────────►│
  │                                          │
  │                      vulnerable_decode() │
  │                      reads alg=none      │
  │                      skips verification  │
  │                      role=admin → OK!    │
  │◄─────────────────────────────────────────│
  │  200 OK + FLAG{jwt_bypass_success}       │
```

---

## Attack 2: RS256→HS256 Confusion Flow

```
Attacker          /public-key         /admin (vulnerable)
  │                   │                    │
  │  GET /public-key  │                    │
  │──────────────────►│                    │
  │◄──────────────────│                    │
  │  RSA public key   │                    │
  │  (PEM bytes)      │                    │
  │                   │                    │
  │  Craft JWT:                            │
  │  header: {alg: HS256}                  │
  │  payload: {role: admin}                │
  │  signature: HMAC(public_key_pem)       │
  │                                        │
  │  GET /admin                            │
  │  Authorization: Bearer forged_token   │
  │───────────────────────────────────────►│
  │                                        │
  │                     vulnerable_decode()│
  │                     reads alg=HS256    │
  │                     verifies with      │
  │                     public_key_pem     │
  │                     HMAC matches!      │
  │                     role=admin → OK!   │
  │◄───────────────────────────────────────│
  │  200 OK + FLAG{jwt_bypass_success}     │
```

---

## Folder Structure

```
jwt-auth-bypass-toolkit/
│
├── vulnerable-api/              ← Person 1
│   ├── app.py                   Main Flask application
│   ├── requirements.txt         Python deps
│   ├── Dockerfile               Container definition
│   ├── generate_keys.py         RSA key generator
│   └── keys/
│       ├── private.pem          RS256 signing key
│       └── public.pem           RS256 verification key (public)
│
├── attacker-toolkit/            ← Person 2
│   ├── none_attack.py           Attack 1: alg:none bypass
│   ├── alg_confusion.py         Attack 2: RS256→HS256
│   ├── forge_claims.py          Attack 3: claim forging
│   ├── utils.py                 Shared helpers
│   └── requirements.txt         Python deps
│
├── docs/                        ← Person 3
│   ├── hardening.md             Security fixes + secure code
│   ├── demo-flow.md             Step-by-step demo + Postman
│   └── architecture.md          This file
│
├── docker-compose.yml           Orchestration
└── README.md                    Project overview
```

---

## Technology Choices

| Component | Technology | Reason |
|---|---|---|
| API framework | Flask 3.0 | Lightweight, easy to read |
| JWT library | PyJWT 2.8 | Industry standard, well-documented |
| Crypto | cryptography 42 | RSA key generation and ops |
| Containerisation | Docker + Compose | Reproducible environment |
| HTTP client | requests | Simple API calls in attacks |

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Use Alternate Authentication Material | T1550.001 | Forged JWT tokens |
| Exploitation of Public-Facing Application | T1190 | /admin endpoint |
| Credential Access | TA0006 | JWT secret inference |

---

## CVE References

| CVE | Description | Affected |
|---|---|---|
| CVE-2015-9235 | alg:none authentication bypass | node-jsonwebtoken < 4.2.2 |
| CVE-2016-5431 | RS256→HS256 confusion | python-jose, PyJWT < 1.0 |
| CVE-2022-21449 | "Psychic Signatures" ECDSA bypass | Java 15-18 |
