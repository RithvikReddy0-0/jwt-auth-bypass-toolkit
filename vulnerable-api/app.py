"""
=============================================================================
VULNERABLE JWT AUTHENTICATION API (CLOUD-NATIVE SIMULATION)
=============================================================================
Simulates a distributed architecture with multiple microservice routes:
- Gateway -> /auth
- Admin Service -> /admin
- Billing Service -> /billing
- Analytics Service -> /analytics
- Tenant Service -> /tenant-data
- Internal API -> /internal

Features:
- Complex multi-tenant RBAC
- Toggleable Vulnerable vs Secure validators via endpoints
=============================================================================
"""

import os
import json
import uuid
import time
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, Blueprint
from functools import wraps
from validators.vulnerable_validator import vulnerable_decode_jwt
from validators.secure_validator import secure_decode_jwt

app = Flask(__name__)

# ─────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────

HS256_SECRET = "supersecretkey123"
KEYS_DIR = os.path.join(os.path.dirname(__file__), "keys")
PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "private.pem")
PUBLIC_KEY_PATH  = os.path.join(KEYS_DIR, "public.pem")

# Ensure keys exist
if not os.path.exists(PRIVATE_KEY_PATH):
    print("Keys not found. Please run generate_keys.py first.")
    exit(1)

with open(PRIVATE_KEY_PATH, "rb") as f:
    PRIVATE_KEY = f.read()

with open(PUBLIC_KEY_PATH, "rb") as f:
    PUBLIC_KEY_PEM = f.read()

# Simulated multi-tenant user database
USERS = {
    "alice": {
        "password": "password123",
        "role": "user",
        "tenant": "companyA",
        "scope": "billing:read",
        "permissions": ["read_profile"],
        "department": "sales",
        "tier": "basic"
    },
    "bob": {
        "password": "letmein",
        "role": "user",
        "tenant": "companyB",
        "scope": "analytics:read",
        "permissions": ["read_profile", "export_data"],
        "department": "marketing",
        "tier": "premium"
    },
    "admin": {
        "password": "adm1n$ecret",
        "role": "admin",
        "tenant": "system",
        "scope": "*",
        "permissions": ["*"],
        "department": "it",
        "tier": "enterprise"
    },
}

# ─────────────────────────────────────────────────────────────
# MIDDLEWARE
# ─────────────────────────────────────────────────────────────

def extract_token():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    return auth_header.split(" ", 1)[1]

def require_jwt_vulnerable(f):
    """Uses the vulnerable validator."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = extract_token()
        if not token:
            return jsonify({"error": "Missing token"}), 401

        payload = vulnerable_decode_jwt(token, PUBLIC_KEY_PEM)
        if payload is None:
            return jsonify({"error": "Invalid or expired token (Vulnerable Validator)"}), 401

        request.jwt_payload = payload
        return f(*args, **kwargs)
    return decorated

def require_jwt_secure(expected_aud):
    """Uses the secure validator."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = extract_token()
            if not token:
                return jsonify({"error": "Missing token"}), 401

            payload = secure_decode_jwt(token, PUBLIC_KEY_PEM, expected_aud, "auth-service")
            if payload is None:
                return jsonify({"error": "Invalid token or replay detected (Secure Validator)"}), 401

            request.jwt_payload = payload
            return f(*args, **kwargs)
        return decorated
    return decorator

def require_claim(claim, expected_value):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            val = request.jwt_payload.get(claim)
            if isinstance(val, list):
                if expected_value not in val and "*" not in val:
                    return jsonify({"error": f"Requires {claim}={expected_value}", "actual": val}), 403
            else:
                if val != expected_value and val != "*":
                    return jsonify({"error": f"Requires {claim}={expected_value}", "actual": val}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


# ─────────────────────────────────────────────────────────────
# BLUEPRINTS (Microservice Simulation)
# ─────────────────────────────────────────────────────────────

# 1. Auth Service
auth_bp = Blueprint("auth", __name__)

@auth_bp.route("/login", methods=["POST"])
def login():
    import jwt
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    alg = data.get("alg", "RS256").upper()
    req_aud = data.get("aud", "frontend-service")

    user = USERS.get(username)
    if not user or user["password"] != password:
        return jsonify({"error": "Invalid credentials"}), 401

    now = int(time.time())
    payload = {
        "sub": username,
        "role": user["role"],
        "tenant": user["tenant"],
        "scope": user["scope"],
        "permissions": user["permissions"],
        "department": user["department"],
        "tier": user["tier"],
        "aud": req_aud,
        "iss": "auth-service",
        "iat": now,
        "exp": now + 3600,
        "jti": str(uuid.uuid4())
    }

    if alg == "RS256":
        token = jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")
    else:
        token = jwt.encode(payload, HS256_SECRET, algorithm="HS256")

    return jsonify({"token": token, "payload_preview": payload})

@auth_bp.route("/public-key", methods=["GET"])
def get_public_key():
    return jsonify({"public_key": PUBLIC_KEY_PEM.decode("utf-8")})


# 2. Admin Service
admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

@admin_bp.route("/vulnerable", methods=["GET"])
@require_jwt_vulnerable
@require_claim("role", "admin")
def admin_vuln():
    return jsonify({"message": "🔓 ADMIN ACCESS GRANTED", "flag": "FLAG{jwt_bypass_success_admin}"})

@admin_bp.route("/secure", methods=["GET"])
@require_jwt_secure("admin-service")
@require_claim("role", "admin")
def admin_secure():
    return jsonify({"message": "🔒 SECURE ADMIN ACCESS GRANTED", "flag": "FLAG{secure_admin_accessed}"})


# 3. Billing Service
billing_bp = Blueprint("billing", __name__, url_prefix="/billing")

@billing_bp.route("/vulnerable", methods=["GET"])
@require_jwt_vulnerable
@require_claim("scope", "billing:read")
def billing_vuln():
    return jsonify({"message": "Billing data accessed", "tenant": request.jwt_payload.get("tenant")})


# 4. Tenant Data Service
tenant_bp = Blueprint("tenant", __name__, url_prefix="/tenant-data")

@tenant_bp.route("/vulnerable/<tenant_id>", methods=["GET"])
@require_jwt_vulnerable
def tenant_vuln(tenant_id):
    token_tenant = request.jwt_payload.get("tenant")
    if token_tenant != tenant_id and token_tenant != "system":
        return jsonify({"error": "Cross-tenant access denied"}), 403
    return jsonify({"message": f"Data for {tenant_id}", "flag": f"FLAG{{tenant_abuse_{tenant_id}}}"})


# 5. Internal API
internal_bp = Blueprint("internal", __name__, url_prefix="/internal")

@internal_bp.route("/vulnerable", methods=["GET"])
@require_jwt_vulnerable
def internal_vuln():
    if request.jwt_payload.get("internal") != True and request.jwt_payload.get("internal") != "true":
         return jsonify({"error": "Internal network only"}), 403
    return jsonify({"message": "Internal systems accessed", "flag": "FLAG{internal_systems_compromised}"})


# Register Blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(billing_bp)
app.register_blueprint(tenant_bp)
app.register_blueprint(internal_bp)

@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "service": "Cloud-Native JWT Attack Platform",
        "routes": [
            "/login", "/public-key", 
            "/admin/vulnerable", "/admin/secure",
            "/billing/vulnerable",
            "/tenant-data/vulnerable/<id>",
            "/internal/vulnerable"
        ]
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
