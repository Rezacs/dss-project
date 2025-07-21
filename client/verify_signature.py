import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

# --- Paste the public key PEM exactly as shown, with line breaks ---
public_key_pem = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxDkucO125fPQbBHLhfa0
S8GPX7h95OFEHMwzMusLzHqi9PrFg+DLlU87sEVHfcuVpC5VeZv3Mi4uis9iv9Tr
JaHUnWm+4LIxC1g7J8AYeS2qt/NHINPTr53LXQcuCpF5I81KPNns0L50sxheJu5o
wTnuvtcAFTemlkeTdlYV6LSBVqFCAJ+YLoJ2xZSt4Lz1hNGqv+mwljQSCqgmpccU
IpBBD5DXR1vIZKOunAnibGP6lEUbP7AyULdOhwXBqhTi0Rlcn3LUckXW6L5fYu14
FByZ21qBPta3ivk/mAv+bdpzL0Ib0JvGI/S2xmAYRlM401LYy+ZPy9eP0jrcUSSB
SwIDAQAB
-----END PUBLIC KEY-----"""

# --- The base64 signature you received from /sign_doc ---
signature_b64 = "Y8qs7kc1pEv+SB+wV+RDMSpVKrA/4GL8qrt4aE8Fieza7S0Yjm0gwA8is9n93sjM/2ZSB5i+aEyH9hAnncaCpJ6n+OOpFF9a/yg4KmY03s+CXf6HY2SDsoe+DSCsxHX5O0/pBjvRuwKzLSzvyNjL52oNk0JF/qjBWqvcumzoXp548DCQZbCe9IKhYnxMS6dMFkXd9+B+MxE9SVNOR/vOO8iIr+6df+yF6NUFjEJ3HiNfvhrbPYV4ZbnCBPEb9fYzEdpX8eSff2RmFQZDP7DN78FOGYbqkADr57QJxFcdAeD213ftxxgP+ars/OlLEG8xv0ddJNMc40qReuNA9DV9xg=="

# --- The document that was signed ---
document = "Hello, sign me!"

# Load the public key
public_key = serialization.load_pem_public_key(public_key_pem.encode())

# Decode the signature from base64
signature = base64.b64decode(signature_b64)

# Verify the signaturecurl -k -X POST https://localhost:5000/sign_doc \
  -H "Content-Type: application/json" \
  -d '{"username":"bob","password":"bobpass123","document":"This is a document signed by Bob."}'

try:
    public_key.verify(
        signature,
        document.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Signature is VALID.")
except Exception as e:
    print("Signature is INVALID:", e)

