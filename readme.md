# Digital Signature Server (DSS)

A secure, extensible, and standards-compliant Digital Signature Server for organizational use, supporting both classic public key infrastructure and X.509 certificate workflows with Certification Authority (CA) integration.

---

## Features

- **User Registration & Key Management:** Secure user registration with password hashing and per-user RSA keypair generation.
- **Encrypted Key Storage:** Private keys are never stored in plaintext—each is encrypted with the user's password.
- **Classic and PKI APIs:** Supports both raw public key exchange and certificate-based trust via a CA.
- **Document Signing:** Authenticated users can digitally sign documents; signatures can be independently verified.
- **Certification Authority Integration:** Users can request, upload, and retrieve X.509 certificates signed by a CA.
- **Complete API Documentation:** Well-documented endpoints, example requests, and error handling.
- **Secure Communication:** All endpoints require HTTPS (TLS).
- **Modular and Extensible:** Designed for easy enhancement and compliance.

---

## Quick Start

### 1. Clone and Install Dependencies

```bash
git clone https://github.com/yourusername/digital-signature-server.git
cd digital-signature-server
pip3 install -r requirements.txt
```

### 2. Generate a Self-Signed Server Certificate

```bash
openssl req -x509 -newkey rsa:2048 -keyout server-key.pem -out server-cert.pem -days 365 -nodes
```

### 3. (Recommended) Set Up a Certification Authority

```bash
mkdir ca
cd ca
openssl genrsa -out ca-key.pem 2048
openssl req -x509 -new -nodes -key ca-key.pem -sha256 -days 3650 -out ca-cert.pem
cd ..
```

### 4. Start the Server

```bash
python3 server.py
```

Server runs on: https://localhost:5000/

---

## API Documentation

### Classic API Endpoints

- **POST /register**: Register a new user
- **GET /get_public_key?username=...**: Retrieve a user's classic public key
- **POST /login**: Authenticate a user
- **POST /sign_doc**: Digitally sign a document
- **POST /delete_keys**: Delete user's keypair and data

### Certificate-based (CA) API Endpoints

- **GET /get_csr?username=...&password=...**: Obtain a Certificate Signing Request (CSR) for a user
- **POST /upload_certificate**: Upload an X.509 certificate signed by the CA for a user
- **GET /get_certificate?username=...**: Retrieve a user's CA-signed certificate

### Other

- **GET /**: Server root info

See the full API Documentation (or API chapter in your docs) for all parameters, sample requests, and responses.

---

## Example Workflow

### 1. Register a User

```bash
curl -k -X POST https://localhost:5000/register \
  -H "Content-Type: application/json" \
  -d '{"username":"bob","password":"bobpass123"}'
```

### 2. Get a CSR for Bob

```bash
curl -k "https://localhost:5000/get_csr?username=bob&password=bobpass123" | jq -r .csr > bob.csr
```

### 3. CA Signs the CSR

```bash
openssl x509 -req -in bob.csr -CA ca/ca-cert.pem -CAkey ca/ca-key.pem -CAcreateserial -out bob-cert.pem -days 365 -sha256
```

### 4. Upload Bob's Certificate

```bash
CERT_CONTENT=$(awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' bob-cert.pem)
curl -k -X POST https://localhost:5000/upload_certificate \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"bob\", \"certificate\":\"$CERT_CONTENT\"}"
```

### 5. Sign a Document

```bash
curl -k -X POST https://localhost:5000/sign_doc \
  -H "Content-Type: application/json" \
  -d '{"username":"bob","password":"bobpass123","document":"Hello from Bob"}'
```

### 6. Retrieve Bob's Certificate

```bash
curl -k "https://localhost:5000/get_certificate?username=bob" | jq -r .certificate > bob-cert.pem
```

---

## Verifying a Signature with Certificate and CA (Python)

```python
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import base64

with open("ca/ca-cert.pem", "rb") as f:
    ca_cert = x509.load_pem_x509_certificate(f.read())
with open("ca/bob-cert.pem", "rb") as f:
    bob_cert = x509.load_pem_x509_certificate(f.read())

# Verify certificate is signed by CA
ca_cert.public_key().verify(
    bob_cert.signature,
    bob_cert.tbs_certificate_bytes,
    padding.PKCS1v15(),
    bob_cert.signature_hash_algorithm
)

# Verify signature
public_key = bob_cert.public_key()
signature = base64.b64decode("...signature from /sign_doc...")
document = "Hello from Bob"
public_key.verify(
    signature,
    document.encode(),
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
```

---

## Security Features

- TLS-encrypted communication
- bcrypt password hashing
- Per-user encrypted private keys
- X.509 certificate support and CA trust
- Detailed error handling
- Modular, auditable codebase

---

## Future Enhancements

- Multi-factor authentication (MFA)
- Automated CA integration (ACME, SCEP)
- Token-based (JWT/OAuth2) authentication
- Hardware Security Module (HSM) integration
- UI dashboard for users and admins
- Full audit logging, rate limiting, and more

---

## License

MIT License (or your choice)

---

## Acknowledgments

Developed as a master's project for the Cybersecurity course at the University of Pisa.  
Thanks to all open-source contributors to Python, Flask, cryptography, and the academic community!

---

**Tips:**
- Replace `yourusername` in the git URL.
- Edit the “API Documentation” link if you post a separate markdown file or have docs elsewhere.
- Customize “License” as needed.
