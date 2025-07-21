import base64
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

# --- Load Bob's certificate (from /get_certificate) ---
with open("/home/iot_ubuntu_intel/dss-project/ca/bob-cert.pem", "rb") as f:
    bob_cert = x509.load_pem_x509_certificate(f.read())

# --- Load your CA's certificate (from ca-cert.pem) ---
with open("/home/iot_ubuntu_intel/dss-project/ca/ca-cert.pem", "rb") as f:
    ca_cert = x509.load_pem_x509_certificate(f.read())

# --- Optionally, verify that Bob's cert was signed by your CA ---
ca_public_key = ca_cert.public_key()
try:
    ca_public_key.verify(
        bob_cert.signature,
        bob_cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        bob_cert.signature_hash_algorithm
    )
    print("Bob's certificate is VALID and signed by the CA.")
except Exception as e:
    print("Certificate verification failed:", e)

# --- Extract public key from Bob's certificate ---
public_key = bob_cert.public_key()

# --- Signature (from /sign_doc), document string ---
signature_b64 = "tktgj2deWdNe8TAHPOct26rK89/KFpOFh6hIDnHMLlvIE96ZteX877xyRt2ZLvnW0QgoocwMd89uHwBLjl9luD26A5DBWtcR3n9vo9SAEnah4npBTajlWTZmKOwNl9pqj9Nd7mc0LvLu77SVMQKhDio5Gf7Vh670j/weH9mET1V70KFQRMrHyNN3UkXEQ30Z12y8+JoBhIB7DF+Stbkwp8uJa2fnCpjMvzUtMBFa2Wik9R1S3s8Uh1VKrIKX+WqfRbMLd+BKCp5asi7adkzzcVOIFwCUNUKpHgn6UsD/9sQedfEP784Q1bom0Ig9WWD5lrzswJxlGmG5aqVU8LBfTw=="
document = "This is a document signed by Bob."

signature = base64.b64decode(signature_b64)

# --- Verify the signature ---
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
    print("Signature is VALID for the document.")
except Exception as e:
    print("Signature is INVALID:", e)
