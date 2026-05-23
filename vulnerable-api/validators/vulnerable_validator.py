import jwt
import hmac
import hashlib
import json
import base64
import time

def vulnerable_decode_jwt(token: str, public_key_pem: bytes) -> dict | None:
    """
    VULNERABLE VALIDATOR:
    - Trusts the 'alg' field from the JWT header.
    - Allows 'none' (CVE-2015-9235).
    - Allows RS256 -> HS256 confusion (CVE-2016-5431).
    - Weak audience and issuer validation (or none).
    - No replay protection (no JTI checking).
    """
    try:
        header = jwt.get_unverified_header(token)
        alg = header.get("alg", "").upper()

        if alg == "NONE":
            # ❌ VULNERABILITY 1: alg=none bypass
            payload = jwt.decode(
                token,
                options={
                    "verify_signature": False,
                    "verify_exp": True,
                },
                algorithms=["none"],
            )
            return payload

        elif alg == "HS256":
            # ❌ VULNERABILITY 2: RS256→HS256 confusion
            # Uses public key PEM as the HMAC secret.
            parts = token.split(".")
            if len(parts) != 3:
                return None

            signing_input = f"{parts[0]}.{parts[1]}".encode("utf-8")

            def _b64d(s):
                s += "=" * (4 - len(s) % 4)
                return base64.urlsafe_b64decode(s)

            expected_sig = hmac.new(
                key=public_key_pem,
                msg=signing_input,
                digestmod=hashlib.sha256,
            ).digest()

            provided_sig = _b64d(parts[2])

            if not hmac.compare_digest(expected_sig, provided_sig):
                return None

            payload_json = _b64d(parts[1])
            payload = json.loads(payload_json)
            
            # Simple expiry check
            if "exp" in payload and payload["exp"] < time.time():
                 return None

            return payload

        elif alg == "RS256":
            # Standard RS256 validation (if the attacker doesn't tamper)
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.backends import default_backend
            
            public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())

            payload = jwt.decode(
                token,
                key=public_key,
                algorithms=["RS256"],
            )
            return payload

        else:
            return None

    except Exception as e:
        return None
