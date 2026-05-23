#!/usr/bin/env python3
"""
=============================================================================
ATTACK CLI — Cloud-Native JWT Attack Platform
=============================================================================
Author: Person 2 (Offensive Security)
Purpose: Master entry point for all offensive JWT modules.
Hackathon Note: This tool automates the manual exploitation steps (like
fetching public keys, Base64URL encoding, and forging payloads) into a 
scalable red-team framework.
"""

import argparse
import sys
import os

# Ensure we can import from current directory
sys.path.append(os.path.dirname(__file__))

from utils import print_banner, print_error

def main():
    parser = argparse.ArgumentParser(
        description="JWT Offensive Toolkit - Master CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Available Commands:
  inspect   — Decode and enumerate JWT claims (claim_enum.py)
  none      — Execute alg:none bypass (none_attack.py)
  confusion — Execute RS256->HS256 algorithm confusion (alg_confusion.py)
  fuzz      — Fuzz authorization endpoints (auth_fuzzer.py)
  audience  — Execute audience confusion attack (audience_confusion.py)
  tenants   — Execute tenant isolation bypass (tenant_abuse.py)
  replay    — Execute token replay attack (replay.py)

Examples:
  python attack.py inspect <TOKEN>
  python attack.py none <TOKEN> --target http://localhost:5001/admin/vulnerable
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Attack module to run")

    # ── Inspect ──
    p_inspect = subparsers.add_parser("inspect", help="Decode and enumerate claims")
    p_inspect.add_argument("token", help="JWT token")

    # ── None ──
    p_none = subparsers.add_parser("none", help="alg:none bypass")
    p_none.add_argument("token", help="Legitimate JWT token")
    p_none.add_argument("--target", required=True, help="Target URL")
    p_none.add_argument("--set", nargs="*", default=[], help="Claims to override (e.g., role=admin)")

    # ── Confusion ──
    p_conf = subparsers.add_parser("confusion", help="RS256->HS256 confusion")
    p_conf.add_argument("--target", required=True, help="Base API URL (to fetch public key)")
    p_conf.add_argument("--endpoint", required=True, help="Target endpoint to attack")
    p_conf.add_argument("--set", nargs="*", default=[], help="Claims to forge")

    # ── Fuzz ──
    p_fuzz = subparsers.add_parser("fuzz", help="Fuzz authorization")
    p_fuzz.add_argument("token", help="Legitimate JWT token")
    p_fuzz.add_argument("--target", required=True, help="Target URL")

    # ── Audience ──
    p_aud = subparsers.add_parser("audience", help="Audience confusion")
    p_aud.add_argument("token", help="Legitimate JWT token")
    p_aud.add_argument("--target", required=True, help="Target URL")

    # ── Tenants ──
    p_ten = subparsers.add_parser("tenants", help="Tenant isolation bypass")
    p_ten.add_argument("token", help="Legitimate JWT token")
    p_ten.add_argument("--target", required=True, help="Target URL (e.g., /tenant-data/vulnerable/companyB)")
    p_ten.add_argument("--tenant", required=True, help="Tenant ID to forge")

    # ── Replay ──
    p_rep = subparsers.add_parser("replay", help="Token replay attack")
    p_rep.add_argument("token", help="Legitimate JWT token")
    p_rep.add_argument("--target", required=True, help="Target URL")
    p_rep.add_argument("--count", type=int, default=5, help="Number of times to replay")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    print_banner(f"Starting Module: {args.command.upper()}")

    # Dispatch to modules
    try:
        if args.command == "inspect":
            import claim_enum
            claim_enum.run(args.token)
            
        elif args.command == "none":
            import none_attack
            none_attack.run(args.token, args.target, args.set)
            
        elif args.command == "confusion":
            import alg_confusion
            alg_confusion.run_attack(args.target, args.endpoint, args.set)
            
        elif args.command == "fuzz":
            import auth_fuzzer
            auth_fuzzer.run(args.token, args.target)
            
        elif args.command == "audience":
            import audience_confusion
            audience_confusion.run(args.token, args.target)
            
        elif args.command == "tenants":
            import tenant_abuse
            tenant_abuse.run(args.token, args.target, args.tenant)
            
        elif args.command == "replay":
            import replay
            replay.run(args.token, args.target, args.count)
            
    except ImportError as e:
        print_error(f"Module not implemented yet: {e}")
    except Exception as e:
        print_error(f"Error executing module: {e}")

if __name__ == "__main__":
    main()
