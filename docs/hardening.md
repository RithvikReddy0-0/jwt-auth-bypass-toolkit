# JWT Security Hardening Guide
## Person 3 — Demo + Security Hardening

---

## Overview

This guide covers the vulnerabilities demonstrated in this toolkit and explains
how to fix each one with production-ready, secure code examples.

---

## Vulnerability 1: alg:none Bypass (CVE-2015-9235)

### What's Broken

```python
# ❌ VULNERABLE: trusts the algorithm from the token header
header = jwt.get_unverified_header(token)
alg = header["alg"]
jwt.decode(token, key, algorithms=[alg])  # attacker controls alg!

# Worse: explicitly disabling verification
jwt.decode(token, options={"verify_signature": False})
```

### The Fix

```python
# ✅ SECURE: always specify an explicit allowlist of algorithms
# NEVER derive the algorithm from the token header

ALLOWED_ALGORITHMS = ["RS256"]  # or ["HS256"] — never both unless required

def secure_decode(token: str) -> dict:
    try:
        payload = jwt.decode(
            token,
            key=PUBLIC_KEY,
            algorithms=ALLOWED_ALGORITHMS,  # ← explicit allowlist, server-controlled
            options={
                "require": ["exp", "iat", "sub"],   # enforce required claims
                "verify_exp": True,
                "verify_iat": True,
            },
        )
        return payload
    except jwt.InvalidTokenError as e:
        raise AuthError(f"Invalid token: {e}")
```

### Why It Works

- `algorithms=["RS256"]` means PyJWT will **reject** any token with `alg=none` or `alg=HS256`
- The server decides the algorithm, not the client
- PyJWT >= 2.0 raises `InvalidAlgorithmError` by default for `none`

---

## Vulnerability 2: RS256 → HS256 Algorithm Confusion (CVE-2016-5431)

### What's Broken

```python
# ❌ VULNERABLE: allows HS256 when RS256 is intended
# The public key is used as HMAC secret — attacker knows it!
jwt.decode(token, key=public_key_pem, algorithms=["HS256"])
```

### The Fix

```python
# ✅ SECURE: pin to a single algorithm; never accept both asymmetric and symmetric

# For RS256 systems:
def secure_decode_rs256(token: str) -> dict:
    return jwt.decode(
        token,
        key=PUBLIC_KEY_OBJECT,          # proper PublicKey object, not raw PEM bytes
        algorithms=["RS256"],           # ONLY RS256 — reject HS256 entirely
    )

# For HS256 systems:
def secure_decode_hs256(token: str) -> dict:
    return jwt.decode(
        token,
        key=HMAC_SECRET,
        algorithms=["HS256"],           # ONLY HS256 — reject RS256 entirely
    )

# If you genuinely need both (rare), use separate endpoints or key IDs:
ALGORITHM_KEY_MAP = {
    "RS256": PUBLIC_KEY_OBJECT,
    "HS256": HMAC_SECRET,
}

def secure_decode_multi(token: str) -> dict:
    header = jwt.get_unverified_header(token)
    alg    = header.get("alg")
    if alg not in ALGORITHM_KEY_MAP:
        raise AuthError(f"Algorithm '{alg}' not permitted")
    return jwt.decode(token, key=ALGORITHM_KEY_MAP[alg], algorithms=[alg])
```

### Key Principles

1. **Never accept `["HS256", "RS256"]` together** in one call without key-type validation
2. Use a proper `PublicKey` object (not raw PEM bytes) as the verification key
3. If you must support multiple algorithms, use `kid` (key ID) in the header and a JWKS endpoint

---

## Vulnerability 3: Weak / Hardcoded Secrets

### What's Broken

```python
# ❌ VULNERABLE
HS256_SECRET = "supersecretkey123"   # guessable, hardcoded, in source control
```

### The Fix

```python
# ✅ SECURE: use environment variables + cryptographically random secrets
import os
import secrets

# In production:
HS256_SECRET = os.environ["JWT_SECRET"]   # loaded from vault / env var

# To generate a secure secret:
# python -c "import secrets; print(secrets.token_hex(32))"
# → e.g. a3f8c2d1e9b4...  (64 hex chars = 256-bit entropy)

# Better yet — switch to RS256 so there's no shared secret at all.
```

---

## Vulnerability 4: Missing Claim Validation

### The Fix

```python
# ✅ SECURE: always validate standard claims
payload = jwt.decode(
    token,
    key=PUBLIC_KEY,
    algorithms=["RS256"],
    options={
        "require": ["exp", "iat", "iss", "sub"],   # reject tokens missing these
    },
    issuer="https://auth.yourapp.com",              # validate iss
    audience="https://api.yourapp.com",             # validate aud
    leeway=10,                                      # 10-second clock skew tolerance
)

# Also check role claims on the application side:
if payload.get("role") not in ("user", "admin"):
    raise AuthError("Invalid role claim")
```

---

## Secure Implementation Checklist

| Check | Status |
|---|---|
| Algorithm allowlist specified server-side | ✅ |
| `alg=none` not in allowlist | ✅ |
| HS256 and RS256 not mixed in same verify call | ✅ |
| Public key is a proper object, not raw bytes | ✅ |
| HMAC secret ≥ 256 bits, from environment variable | ✅ |
| `exp` claim validated | ✅ |
| `iss` and `aud` claims validated | ✅ |
| Short token lifetime (≤ 15 min for access tokens) | ✅ |
| Refresh tokens used for longer sessions | ✅ |
| Tokens invalidated on logout (deny-list or short TTL) | ✅ |
| HTTPS enforced (tokens never sent over plain HTTP) | ✅ |
| Rate limiting on /login endpoint | ✅ |

---

## Recommended Libraries & Settings

### Python / PyJWT

```bash
pip install PyJWT==2.8.0 cryptography==42.0.8
```

```python
import jwt

# Always use this pattern:
payload = jwt.decode(
    token,
    key=public_key,
    algorithms=["RS256"],              # explicit, server-controlled
    options={"require": ["exp", "sub"]},
)
```

### Node.js / jsonwebtoken

```js
// ❌ Vulnerable
jwt.verify(token, publicKey);   // missing algorithms option

// ✅ Secure
jwt.verify(token, publicKey, { algorithms: ['RS256'] });
```

### Java / jjwt

```java
// ✅ Secure
Jwts.parserBuilder()
    .setSigningKey(publicKey)
    .requireAlgorithm("RS256")          // explicit pinning
    .build()
    .parseClaimsJws(token);
```

---

## References

- [RFC 7519 — JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
- [CVE-2015-9235 — alg:none](https://nvd.nist.gov/vuln/detail/CVE-2015-9235)
- [CVE-2016-5431 — Algorithm Confusion](https://nvd.nist.gov/vuln/detail/CVE-2016-5431)
- [PortSwigger — JWT Attacks](https://portswigger.net/web-security/jwt)
- [OWASP — JSON Web Token Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [MITRE ATT&CK T1550.001](https://attack.mitre.org/techniques/T1550/001/)
