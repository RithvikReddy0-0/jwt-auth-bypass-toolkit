"""
=============================================================================
RSA KEY GENERATION — Person 1
=============================================================================
Generates a 2048-bit RSA key pair used by the vulnerable API for RS256 JWTs.

Run ONCE before starting the API:
    python generate_keys.py

Output:
    keys/private.pem  — RS256 signing key (keep secret)
    keys/public.pem   — RS256 verification key (served at /public-key)

The public key is intentionally exposed via the API — this enables the
RS256→HS256 confusion attack demonstrated in the attacker toolkit.
=============================================================================
"""

import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

KEYS_DIR = os.path.join(os.path.dirname(__file__), "keys")


def generate_rsa_keypair():
    """Generate a 2048-bit RSA key pair and save to PEM files."""
    os.makedirs(KEYS_DIR, exist_ok=True)

    print("[*] Generating 2048-bit RSA key pair...")

    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )

    # Serialize private key to PEM
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Serialize public key to PEM
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Write to files
    private_path = os.path.join(KEYS_DIR, "private.pem")
    public_path  = os.path.join(KEYS_DIR, "public.pem")

    with open(private_path, "wb") as f:
        f.write(private_pem)

    with open(public_path, "wb") as f:
        f.write(public_pem)

    print(f"[+] Private key saved: {private_path}")
    print(f"[+] Public key saved:  {public_path}")
    print()
    print("Public Key (PEM):")
    print(public_pem.decode())
    print("[!] The public key will be exposed via /public-key endpoint.")
    print("[!] Attackers will use it as an HMAC secret in the RS256→HS256 attack.")


if __name__ == "__main__":
    generate_rsa_keypair()
