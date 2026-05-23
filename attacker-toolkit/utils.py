"""
=============================================================================
UTILS — Shared Attacker Toolkit Utilities
=============================================================================
Person 2 — Offensive JWT Attack Toolkit

Shared helper functions used across all attack scripts:
  - Base64url encoding / decoding
  - JWT part extraction (without verification)
  - Pretty printing
  - Terminal colour codes
=============================================================================
"""

import json
import base64
import struct
from datetime import datetime


# ─────────────────────────────────────────────────────────────
# ANSI Colours
# ─────────────────────────────────────────────────────────────

class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"


def print_banner(title: str):
    width = 62
    print()
    print(C.CYAN + "═" * width + C.RESET)
    print(C.BOLD + C.CYAN + f"  {title}" + C.RESET)
    print(C.CYAN + "═" * width + C.RESET)
    print()


def print_success(msg: str):
    print(f"{C.GREEN}[+]{C.RESET} {msg}")


def print_error(msg: str):
    print(f"{C.RED}[-]{C.RESET} {msg}")


def print_info(msg: str):
    print(f"{C.BLUE}[*]{C.RESET} {msg}")


def print_warn(msg: str):
    print(f"{C.YELLOW}[!]{C.RESET} {msg}")


# ─────────────────────────────────────────────────────────────
# Base64url Helpers
# ─────────────────────────────────────────────────────────────

def b64url_encode(data) -> str:
    """
    Encode data as base64url (no padding).
    Accepts str, bytes, or dict.
    """
    if isinstance(data, dict):
        data = json.dumps(data, separators=(",", ":"))
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def b64url_decode(encoded: str) -> bytes:
    """
    Decode base64url string (adds padding if needed).
    Returns raw bytes.
    """
    # Add padding
    padded = encoded + "=" * (4 - len(encoded) % 4)
    return base64.urlsafe_b64decode(padded)


def b64url_decode_json(encoded: str) -> dict:
    """Decode base64url string and parse as JSON."""
    return json.loads(b64url_decode(encoded).decode("utf-8"))


# ─────────────────────────────────────────────────────────────
# JWT Parsing (WITHOUT Verification)
# ─────────────────────────────────────────────────────────────

def decode_jwt_parts(token: str) -> tuple[dict, dict, str]:
    """
    Split a JWT into its three parts and decode header + payload.
    Does NOT verify the signature.

    Returns:
        (header_dict, payload_dict, signature_b64url)
    """
    parts = token.split(".")
    if len(parts) not in (2, 3):
        raise ValueError(f"Invalid JWT format — expected 2 or 3 parts, got {len(parts)}")

    header_enc  = parts[0]
    payload_enc = parts[1]
    sig_enc     = parts[2] if len(parts) == 3 else ""

    header  = b64url_decode_json(header_enc)
    payload = b64url_decode_json(payload_enc)

    return header, payload, sig_enc


def get_jwt_header(token: str) -> dict:
    """Return just the header of a JWT."""
    header, _, _ = decode_jwt_parts(token)
    return header


def get_jwt_payload(token: str) -> dict:
    """Return just the payload of a JWT."""
    _, payload, _ = decode_jwt_parts(token)
    return payload


# ─────────────────────────────────────────────────────────────
# Pretty Printing
# ─────────────────────────────────────────────────────────────

def _format_timestamp(value) -> str:
    """Format a Unix timestamp as human-readable string."""
    try:
        return datetime.utcfromtimestamp(int(value)).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(value)


def pretty_print_jwt(token: str):
    """
    Pretty print a JWT's header and payload with syntax highlighting.
    Does NOT verify the signature.
    """
    try:
        header, payload, sig = decode_jwt_parts(token)
    except ValueError as e:
        print_error(f"Cannot decode token: {e}")
        return

    print(C.BOLD + "  ── Header ──" + C.RESET)
    for k, v in header.items():
        print(f"    {C.CYAN}{k:12}{C.RESET} : {C.WHITE}{v}{C.RESET}")

    print()
    print(C.BOLD + "  ── Payload ──" + C.RESET)
    for k, v in payload.items():
        if k in ("exp", "iat", "nbf"):
            formatted = f"{v}  ({_format_timestamp(v)})"
            print(f"    {C.CYAN}{k:12}{C.RESET} : {C.YELLOW}{formatted}{C.RESET}")
        elif k == "role" and v == "admin":
            print(f"    {C.CYAN}{k:12}{C.RESET} : {C.RED}{C.BOLD}{v}{C.RESET}")
        else:
            print(f"    {C.CYAN}{k:12}{C.RESET} : {C.WHITE}{v}{C.RESET}")

    print()
    sig_preview = (sig[:32] + "...") if len(sig) > 32 else (sig if sig else "(empty — alg:none)")
    sig_colour  = C.RED if not sig else C.GREEN
    print(C.BOLD + "  ── Signature ──" + C.RESET)
    print(f"    {sig_colour}{sig_preview}{C.RESET}")
    print()


def print_token_diff(original: str, forged: str):
    """Show before/after comparison of original vs forged token."""
    try:
        orig_h, orig_p, _ = decode_jwt_parts(original)
        forg_h, forg_p, _ = decode_jwt_parts(forged)
    except Exception:
        return

    print(C.BOLD + "\n  ── Token Comparison ──" + C.RESET)

    # Header changes
    all_keys = set(orig_h) | set(forg_h)
    for k in all_keys:
        o = orig_h.get(k, "—")
        f = forg_h.get(k, "—")
        if o != f:
            print(f"  Header.{k}: {C.RED}{o}{C.RESET} → {C.GREEN}{f}{C.RESET}")

    # Payload changes
    all_keys = set(orig_p) | set(forg_p)
    for k in all_keys:
        o = orig_p.get(k, "—")
        f = forg_p.get(k, "—")
        if o != f:
            print(f"  Payload.{k}: {C.RED}{o}{C.RESET} → {C.GREEN}{f}{C.RESET}")

    print()
