import requests
import time
from utils import print_info, print_success, print_error

def run(token: str, target: str, count: int):
    print_info(f"Starting Replay Attack: {count} requests to {target}")
    
    successes = 0
    blocks = 0
    
    headers = {"Authorization": f"Bearer {token}"}
    
    for i in range(count):
        print_info(f"Request {i+1}/{count}...")
        try:
            resp = requests.get(target, headers=headers, timeout=5)
            
            if resp.status_code == 200:
                print_success(f"  Accepted! (Status {resp.status_code}) - Vulnerable to replay.")
                successes += 1
            elif resp.status_code == 401:
                print_error(f"  Blocked! (Status 401) - {resp.json().get('error', 'Unauthorized')}")
                blocks += 1
            else:
                print(f"  Status {resp.status_code}: {resp.text.strip()}")
                
        except requests.ConnectionError:
            print_error(f"  Connection failed.")
            break
            
        time.sleep(0.5) # Slight delay
        
    print_info(f"Replay Summary: {successes} Accepted, {blocks} Blocked.")
    if successes > 0 and blocks == 0:
        print_success("Target is VULNERABLE to replay attacks (no JTI tracking).")
    elif blocks > 0:
        print_success("Target is SECURE against replay attacks.")
