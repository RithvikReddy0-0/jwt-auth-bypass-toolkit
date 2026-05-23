import os
import json
import base64

def b64url_encode(data):
    if isinstance(data, dict):
        data = json.dumps(data, separators=(",", ":"))
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

def generate():
    print("Generating JWT Edge Cases...")
    
    # Base payloads
    h_b = {"alg": "RS256", "typ": "JWT"}
    p_b = {"sub": "alice", "role": "user"}
    
    # 1. Empty Signature
    h1 = b64url_encode(h_b)
    p1 = b64url_encode(p_b)
    print(f"1. Empty Signature: {h1}.{p1}.")
    
    # 2. Huge Payload (DOS attempt)
    p_huge = p_b.copy()
    p_huge["padding"] = "A" * 10000
    p2 = b64url_encode(p_huge)
    print(f"2. Huge Payload (10k chars): {h1}.{p2}.fake_sig")
    
    # 3. Unicode Homoglyphs (admin vs аdmin - Cyrillic 'a')
    p_homo = p_b.copy()
    p_homo["role"] = "аdmin" 
    p3 = b64url_encode(p_homo)
    print(f"3. Unicode Homoglyph role: {h1}.{p3}.fake_sig")
    
    # 4. Duplicate Claims (invalid JSON)
    # This requires raw string manipulation
    raw_payload = '{"sub":"alice","role":"user","role":"admin"}'
    p4 = b64url_encode(raw_payload.encode('utf-8'))
    print(f"4. Duplicate Claims (role=user, role=admin): {h1}.{p4}.fake_sig")

if __name__ == "__main__":
    generate()
