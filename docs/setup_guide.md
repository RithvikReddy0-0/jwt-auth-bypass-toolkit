# Setup Documentation

This guide provides detailed instructions on how to set up the Vulnerable JWT API and the Attacker Toolkit. You can choose between running everything locally using Python or running it in an isolated Docker environment.

---

## 🐳 Option A: Docker (Recommended)

The easiest way to run the project is using Docker Compose. This automatically spins up the API on port 5001 and sets up an isolated attacker container with all dependencies installed.

### 1. Build and Start the Environment
Navigate to the root directory of the project and run:
```bash
docker compose up -d --build
```

### 2. Verify the API is Running
Wait a few seconds, then verify the API is running by hitting the root endpoint:
```bash
curl http://localhost:5001/
```

### 3. Run the Attacker Toolkit
You can execute commands inside the `attacker` container.
```bash
# Log in to get a token
TOKEN=$(curl -s -X POST http://localhost:5001/login -H "Content-Type: application/json" -d '{"username":"alice","password":"password123"}' | jq -r .token)

# Run the 'none' attack
docker compose exec attacker python attack.py none $TOKEN --target http://api:5001/admin/vulnerable --set role=admin

# Run the 'confusion' attack
docker compose exec attacker python attack.py confusion --target http://api:5001 --endpoint http://api:5001/admin/vulnerable --set role=admin

# Enumerate Claims
docker compose exec attacker python attack.py inspect $TOKEN

# Fuzz Authorization Boundaries
docker compose exec attacker python attack.py fuzz $TOKEN --target http://api:5001/admin/vulnerable

# Tenant Isolation Abuse
docker compose exec attacker python attack.py tenants $TOKEN --target http://api:5001/tenant-data/vulnerable/companyB --tenant companyB

# Token Replay Attack (Blocked by Secure Target)
docker compose exec attacker python attack.py replay $TOKEN --target http://api:5001/admin/vulnerable --count 5

# Audience Confusion Attack (Blocked by Secure Target)
docker compose exec attacker python attack.py audience $TOKEN --target http://api:5001/admin/vulnerable
```

### 4. Stop the Environment
```bash
docker compose down
```

---

## 🐍 Option B: Local Python

If you prefer to run the API directly on your host machine, follow these steps.

### 1. Setup the Vulnerable API

First, generate the RSA keys required for the `RS256` asymmetric cryptography and start the server.

```bash
cd vulnerable-api

# Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Generate the public/private key pair
python generate_keys.py

# Start the Flask API on port 5001
python app.py
```
*(Leave this terminal window open)*

### 2. Setup the Attacker Toolkit

Open a **new terminal window** and navigate to the toolkit folder.

```bash
cd attacker-toolkit

# Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Execute Attacks

Now you can use the master CLI to launch attacks against your local API.

```bash
# Log in as a normal user to get a base token
TOKEN=$(curl -s -X POST http://localhost:5001/login -H "Content-Type: application/json" -d '{"username":"alice","password":"password123"}' | jq -r .token)

# Enumerate Claims
python attack.py inspect $TOKEN

# Fuzz Authorization Boundaries
python attack.py fuzz $TOKEN --target http://localhost:5001/admin/vulnerable

# Attack 1: alg:none Bypass
python attack.py none $TOKEN --target http://localhost:5001/admin/vulnerable --set role=admin

# Attack 2: RS256→HS256 Algorithm Confusion
python attack.py confusion --target http://localhost:5001 --endpoint http://localhost:5001/admin/vulnerable --set role=admin

# Attack 3: Tenant Isolation Abuse
python attack.py tenants $TOKEN --target http://localhost:5001/tenant-data/vulnerable/companyB --tenant companyB

# Attack 4: Token Replay Attack
python attack.py replay $TOKEN --target http://localhost:5001/admin/vulnerable --count 5

# Attack 5: Audience Confusion Attack
python attack.py audience $TOKEN --target http://localhost:5001/admin/vulnerable
```
