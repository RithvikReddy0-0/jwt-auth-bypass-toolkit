import json
from utils import decode_jwt_parts, print_info, print_success, print_warn, C

def run(token: str):
    print_info("Decoding JWT without verification...")
    try:
        header, payload, _ = decode_jwt_parts(token)
    except Exception as e:
        print(f"Error decoding: {e}")
        return

    print("\n" + C.BOLD + "Detected Claims:" + C.RESET)
    print("-" * 20)
    for k, v in payload.items():
        if k in ["role", "tenant", "tier", "scope", "permissions", "department"]:
            print(f"{C.CYAN}{k}{C.RESET}={C.YELLOW}{v}{C.RESET}")
        elif k in ["internal", "admin", "superuser"]:
             print(f"{C.CYAN}{k}{C.RESET}={C.RED}{v}{C.RESET}")
        else:
            print(f"{k}={v}")

    print("\n" + C.BOLD + "Possible Escalation Targets:" + C.RESET)
    print("-" * 28)
    
    if "role" in payload and payload["role"] != "admin":
        print_success(f"role -> admin, superadmin, root")
    
    if "tenant" in payload:
        print_success(f"tenant -> companyB, system, master")
        
    if "tier" in payload and payload["tier"] != "enterprise":
        print_success(f"tier -> premium, enterprise, unlimited")
        
    if "scope" in payload:
        print_success(f"scope -> *, admin:*, billing:write")
        
    if "internal" not in payload:
        print_success(f"Missing claim -> Inject 'internal=true'")

    print("\n" + C.BOLD + "Suggested Next Steps:" + C.RESET)
    print("1. Run `python attack.py fuzz <TOKEN> --target <URL>` to test authorization boundaries.")
    print("2. Run `python attack.py none <TOKEN> --target <URL> --set role=admin` to attempt alg:none bypass.")
