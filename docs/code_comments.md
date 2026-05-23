# Code Comments & Explanations

As requested for the rubric, this document explicitly lists out the literal code comments injected directly into the source code to explain the vulnerabilities, security features, and exploit mechanisms.

---

## 1. Vulnerable API Endpoints (`vulnerable-api/app.py`)

**Admin Vulnerable Endpoint (Line 197-201):**
```python
    """
    [VULNERABLE ENDPOINT]
    This route relies on `require_jwt_vulnerable` which allows alg:none and RS256->HS256 confusion.
    If the crypto bypass is successful, the attacker can forge the role=admin claim.
    """
```

**Admin Secure Endpoint (Line 208-212):**
```python
    """
    [SECURE ENDPOINT]
    This route uses `require_jwt_secure` which implements Strict Algorithm Pinning.
    It is immune to the bypass attacks.
    """
```

**Billing Scope Vulnerable Endpoint (Line 223-226):**
```python
    """
    [VULNERABLE ENDPOINT]
    Used to demonstrate horizontal privilege escalation via Scope forging.
    """
```

**Tenant Data Vulnerable Endpoint (Line 236-240):**
```python
    """
    [VULNERABLE ENDPOINT]
    Used to demonstrate Tenant Isolation Abuse. By forging the 'tenant' claim, 
    an attacker can breach data belonging to other companies.
    """
```

---

## 2. Vulnerable JWT Cryptography (`vulnerable-api/validators/vulnerable_validator.py`)

**Global Validator Warning (Line 9-16):**
```python
    """
    VULNERABLE VALIDATOR:
    - Trusts the 'alg' field from the JWT header.
    - Allows 'none' (CVE-2015-9235).
    - Allows RS256 -> HS256 confusion (CVE-2016-5431).
    - Weak audience and issuer validation (or none).
    - No replay protection (no JTI checking).
    """
```

**Alg:none Implementation Bypass (Line 21-22):**
```python
        if alg == "NONE":
            # ❌ VULNERABILITY 1: alg=none bypass
```

**RS256→HS256 Confusion Flaw (Line 33-35):**
```python
        elif alg == "HS256":
            # ❌ VULNERABILITY 2: RS256→HS256 confusion
            # Uses public key PEM as the HMAC secret.
```

---

## 3. Exploit Implementation Details (`attacker-toolkit/`)

**Dropping the Signature (`none_attack.py`, Line 69):**
```python
    # alg=none → signature MUST be empty string (just a trailing dot)
```

**Symmetric Key Forgery (`alg_confusion.py`, Line 102-103):**
```python
    # ── THE ATTACK: sign with PUBLIC KEY as HMAC secret
    # The public key PEM is used as the raw bytes secret for HMAC-SHA256
```
