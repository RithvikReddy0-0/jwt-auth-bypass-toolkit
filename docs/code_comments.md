# Code Comments & Explanations

This document serves as the formal "Code Comments File" for the hackathon rubric. Below are the critical code segments where vulnerabilities were intentionally introduced and where our offensive toolkit exploits them.

---

## 1. Vulnerable API

### `vulnerable-api/app.py`
This is the main entry point for the microservice.
* **Line 57 (`/login`):** Validates user credentials. Crucially, it accepts an `alg` parameter from the user, demonstrating a failure to enforce secure cryptographic defaults.
* **Line 77 (`/admin/vulnerable`):** The primary capture-the-flag endpoint. Uses `@require_jwt` from the vulnerable validator.
* **Line 93 (`/tenant-data/vulnerable/<tenant_id>`):** Relies blindly on the `tenant` claim extracted from the JWT to enforce database isolation, allowing horizontal privilege escalation if the signature is bypassed.
* **Line 115 (`/internal/vulnerable`):** Expects the JWT's `aud` claim to be "internal-api", demonstrating failure in audience validation when the signature is bypassed.

### `vulnerable-api/validators/vulnerable_validator.py`
This file contains the core cryptographic implementation flaws that make the attacks possible.
* **Line 46 (`# [VULNERABLE ENDPOINT - ALGORITHM CONFUSION]`):** `if token_alg == "HS256":` - The server dynamically changes its verification strategy based on the unverified, untrusted `alg` header provided by the attacker.
* **Line 50 (`# [VULNERABLE ENDPOINT - SIGNATURE BYPASS]`):** `if token_alg == "none":` - Explicitly bypasses `jwt.decode` signature verification entirely if the attacker specifies the "none" algorithm.
* **Line 33 (`# NO REPLAY PROTECTION`):** The code decodes the JWT without maintaining a blacklist or tracking the `jti` (JWT ID), allowing infinite reuse of tokens.

---

## 2. Attacker Toolkit

### `attacker-toolkit/none_attack.py`
Automates the CVE-2015-9235 exploit.
* **Line 26:** `header = {"alg": "none", "typ": "JWT"}` - Replaces the original cryptographic header.
* **Line 30-31:** Automatically injects the requested elevated privileges (e.g., `role: admin`) into the payload.
* **Line 37:** `return f"{b64_header}.{b64_payload}."` - Re-assembles the JWT and intentionally drops the cryptographic signature entirely.

### `attacker-toolkit/alg_confusion.py`
Automates the CVE-2016-5431 exploit.
* **Line 23:** Fetches the RSA public key directly from the vulnerable server's `/public-key` endpoint.
* **Line 40:** `encoded_key = base64.b64encode(public_key).decode('utf-8')` - Encodes the RSA public key into Base64 format to serve as the symmetric HMAC secret.
* **Line 50:** `jwt.encode(..., key=public_key, algorithm="HS256")` - Signs the forged payload using HMAC-SHA256, feeding the public key to the crypto library as if it were a shared symmetric secret.
