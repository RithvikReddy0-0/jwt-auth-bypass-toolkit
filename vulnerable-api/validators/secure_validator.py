import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# In a real system, you'd use a Redis cache or database for seen JTIs
_SEEN_JTIS = set()

def secure_decode_jwt(token: str, public_key_pem: bytes, expected_aud: str, expected_iss: str) -> dict | None:
    """
    SECURE VALIDATOR:
    - Strict algorithm pinning (RS256 only).
    - Rejects 'none' entirely.
    - Requires and validates 'aud' and 'iss'.
    - Tracks 'jti' to prevent replay attacks.
    """
    try:
        public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())

        # ✅ SECURE: Strict validation rules
        payload = jwt.decode(
            token,
            key=public_key,
            algorithms=["RS256"],  # Only allow RS256
            audience=expected_aud,
            issuer=expected_iss,
            options={
                "require": ["exp", "iat", "aud", "iss", "jti", "sub", "role"],
                "verify_exp": True,
                "verify_iat": True,
                "verify_aud": True,
                "verify_iss": True,
            }
        )

        # ✅ SECURE: Replay Protection
        jti = payload.get("jti")
        if jti in _SEEN_JTIS:
            print(f"[SECURE VALIDATOR] Blocked replay attack for JTI: {jti}")
            return None
        _SEEN_JTIS.add(jti)

        return payload

    except jwt.ExpiredSignatureError:
        print("[SECURE VALIDATOR] Token expired.")
        return None
    except jwt.InvalidTokenError as e:
        print(f"[SECURE VALIDATOR] Validation failed: {e}")
        return None
    except Exception as e:
        return None
