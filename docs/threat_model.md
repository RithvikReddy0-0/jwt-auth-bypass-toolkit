# Threat Model

## System Overview
The architecture simulates a modern Cloud-Native microservices environment. Authentication is handled centrally by an Auth Gateway, which issues stateless JSON Web Tokens (JWTs). Downstream microservices (Admin, Billing, Tenant Data) do not contact a central database for authorization; instead, they completely trust the claims embedded within the cryptographically signed JWT.

## Trust Boundaries
1. **External Untrusted Zone:** The internet/user domain. Users can intercept, read, and manipulate their own JWTs.
2. **API Gateway Boundary:** The Auth service that validates initial credentials and generates the JWT.
3. **Internal Microservice Boundary:** The backend APIs that consume the JWT. They inherently trust the API Gateway. The vulnerability exists exactly at this boundary line—if the cryptographic verification is bypassed, the entire internal trust model collapses.

## STRIDE Threat Analysis

### 1. Spoofing (Identity Forgery)
- **Threat:** An attacker alters the `sub` (subject) or `role` claims in the JWT payload to masquerade as an administrator.
- **Vulnerability:** CVE-2015-9235 (alg:none) allows an attacker to strip the signature and force the server to accept the forged identity without any cryptographic validation.
- **Impact:** Complete system compromise. 
- **Mitigation:** Strict Algorithm Pinning. The backend must hardcode `algorithms=["RS256"]` and ignore the user-provided `alg` header.

### 2. Tampering (Signature Manipulation)
- **Threat:** An attacker alters the payload to modify scopes and re-signs the token.
- **Vulnerability:** CVE-2016-5431 (Algorithm Confusion). An attacker forces the backend to evaluate an asymmetric signature (RS256) symmetrically (HS256) using the publicly available RSA Public Key as the HMAC secret.
- **Impact:** Vertical Privilege Escalation. The attacker mathematically proves authenticity using the server's own public key against it.
- **Mitigation:** Enforcing strong, explicit key validation mappings. In Python's `jwt` library, passing an RSA public key to an HS256 algorithm securely throws an `InvalidKeyError` in modern versions.

### 3. Information Disclosure (Cross-Tenant Breach)
- **Threat:** A user belonging to `companyA` modifies the `tenant` claim in their JWT to read data belonging to `companyB`.
- **Vulnerability:** Weak authorization boundary combined with cryptographic bypass.
- **Impact:** Horizontal Privilege Escalation resulting in a multi-tenant data breach.
- **Mitigation:** Enforcing strict cryptographic checks (stopping the forgery) combined with defense-in-depth database-level Row Level Security (RLS) linked to the authenticated session context.

### 4. Elevation of Privilege (Audience Abuse)
- **Threat:** A token generated for a low-privilege `frontend-service` is captured and submitted to a high-privilege `internal-api`.
- **Vulnerability:** Missing Audience (`aud`) validation.
- **Impact:** Cross-service authorization bypass.
- **Mitigation:** The microservice must explicitly validate the `aud` claim during decoding to ensure the token was generated specifically for its use.

## Systemic Risks in Stateless Authentication
The fundamental flaw demonstrated in this project is **Trusting User Input for Cryptographic Control Paths**. 

By allowing the attacker to specify *how* the token should be validated (via the `alg` header), the server surrenders its security posture to the client. This violates the core principle of Zero Trust architecture, where security mechanisms must be centrally dictated and enforced regardless of client input.
