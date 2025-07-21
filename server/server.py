from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import bcrypt
import shelve
import base64
from cryptography import x509
from cryptography.x509.oid import NameOID

app = Flask(__name__)

DB_FILE = 'users.db'

def generate_csr(private_key, username, email="user@example.com"):
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, username),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email)
    ])).sign(private_key, hashes.SHA256(), default_backend())
    return csr.public_bytes(serialization.Encoding.PEM)

@app.route('/')
def hello():
    return "Hello, this is the Digital Signature Server!"

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'Username and password are required.'}), 400

    with shelve.open(DB_FILE) as db:
        if username in db:
            return jsonify({'error': 'User already exists.'}), 409

        # Hash password
        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

        # Generate key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # Encrypt private key with user's password (simplified)
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        )

        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Store everything
        db[username] = {
            'pw_hash': base64.b64encode(pw_hash).decode(),
            'private_key': base64.b64encode(private_bytes).decode(),
            'public_key': base64.b64encode(public_bytes).decode(),
        }

    return jsonify({'message': 'User registered and keys generated.'}), 201


@app.route('/get_public_key', methods=['GET'])
def get_public_key():
    username = request.args.get('username')
    if not username:
        return jsonify({'error': 'Username is required as query parameter.'}), 400

    with shelve.open(DB_FILE) as db:
        user = db.get(username)
        if not user:
            return jsonify({'error': 'User not found.'}), 404
        public_key_b64 = user['public_key']
        # You can return directly or decode for PEM format
        public_key_pem = base64.b64decode(public_key_b64).decode()
        return jsonify({'username': username, 'public_key': public_key_pem}), 200
        
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'Username and password are required.'}), 400

    with shelve.open(DB_FILE) as db:
        user = db.get(username)
        if not user:
            return jsonify({'error': 'User not found.'}), 404

        stored_pw_hash = base64.b64decode(user['pw_hash'])
        if bcrypt.checkpw(password.encode(), stored_pw_hash):
            return jsonify({'message': 'Login successful.'}), 200
        else:
            return jsonify({'error': 'Invalid password.'}), 401

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

@app.route('/sign_doc', methods=['POST'])
def sign_doc():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    document = data.get('document')
    if not username or not password or not document:
        return jsonify({'error': 'Username, password, and document are required.'}), 400

    with shelve.open(DB_FILE) as db:
        user = db.get(username)
        if not user:
            return jsonify({'error': 'User not found.'}), 404

        stored_pw_hash = base64.b64decode(user['pw_hash'])
        if not bcrypt.checkpw(password.encode(), stored_pw_hash):
            return jsonify({'error': 'Invalid password.'}), 401

        # Decrypt private key
        try:
            private_key = serialization.load_pem_private_key(
                base64.b64decode(user['private_key']),
                password=password.encode(),
                backend=default_backend()
            )
        except Exception as e:
            return jsonify({'error': f'Could not decrypt private key: {str(e)}'}), 500

        # Sign the document
        signature = private_key.sign(
            document.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        signature_b64 = base64.b64encode(signature).decode()
        return jsonify({'signature': signature_b64}), 200

@app.route('/delete_keys', methods=['POST'])
def delete_keys():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'Username and password are required.'}), 400

    with shelve.open(DB_FILE, writeback=True) as db:
        user = db.get(username)
        if not user:
            return jsonify({'error': 'User not found.'}), 404

        stored_pw_hash = base64.b64decode(user['pw_hash'])
        if not bcrypt.checkpw(password.encode(), stored_pw_hash):
            return jsonify({'error': 'Invalid password.'}), 401

        # Delete user entry
        del db[username]

    return jsonify({'message': 'Key pair and user data deleted.'}), 200
    
@app.route('/get_csr', methods=['GET'])
def get_csr():
    username = request.args.get('username')
    password = request.args.get('password')
    if not username or not password:
        return jsonify({'error': 'Username and password are required.'}), 400

    with shelve.open(DB_FILE) as db:
        user = db.get(username)
        if not user:
            return jsonify({'error': 'User not found.'}), 404
        stored_pw_hash = base64.b64decode(user['pw_hash'])
        if not bcrypt.checkpw(password.encode(), stored_pw_hash):
            return jsonify({'error': 'Invalid password.'}), 401

        private_key = serialization.load_pem_private_key(
            base64.b64decode(user['private_key']),
            password=password.encode(),
            backend=default_backend()
        )

        # Generate CSR
        csr_pem = generate_csr(private_key, username)
        return jsonify({'csr': csr_pem.decode()}), 200

@app.route('/upload_certificate', methods=['POST'])
def upload_certificate():
    data = request.get_json()
    username = data.get('username')
    certificate_pem = data.get('certificate')
    if not username or not certificate_pem:
        return jsonify({'error': 'Username and certificate are required.'}), 400

    with shelve.open(DB_FILE, writeback=True) as db:
        user = db.get(username)
        if not user:
            return jsonify({'error': 'User not found.'}), 404
        user['certificate'] = certificate_pem
    return jsonify({'message': 'Certificate uploaded and stored.'}), 200


@app.route('/get_certificate', methods=['GET'])
def get_certificate():
    username = request.args.get('username')
    if not username:
        return jsonify({'error': 'Username is required.'}), 400

    with shelve.open(DB_FILE) as db:
        user = db.get(username)
        if not user or 'certificate' not in user:
            return jsonify({'error': 'Certificate not found for user.'}), 404
        return jsonify({'certificate': user['certificate']}), 200



if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=5000,
        ssl_context=('server-cert.pem', 'server-key.pem')
    )
    

