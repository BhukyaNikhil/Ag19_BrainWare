from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64

# Load or generate plant's private key
def load_plant_private_key(plant_id):
    keys_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'keys')
    os.makedirs(keys_dir, exist_ok=True)
    key_path = os.path.join(keys_dir, f'{plant_id}_private.pem')
    try:
        with open(key_path, 'rb') as f:
            return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    except FileNotFoundError:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        with open(key_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        # Also save public key for server
        public_key = private_key.public_key()
        pub_key_path = os.path.join(keys_dir, f'{plant_id}_public.pem')
        with open(pub_key_path, 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        return private_key

# Sign data
def sign_data(data, plant_id):
    private_key = load_plant_private_key(plant_id)
    signature = private_key.sign(
        data.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

# Load server's public key (in real scenario, fetch or have it)
def load_server_public_key():
    keys_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'keys')
    os.makedirs(keys_dir, exist_ok=True)
    key_path = os.path.join(keys_dir, 'server_public.pem')
    try:
        with open(key_path, 'rb') as f:
            return serialization.load_pem_public_key(f.read(), backend=default_backend())
    except FileNotFoundError:
        # Generate if not exists
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        # Save private for server
        priv_path = os.path.join(keys_dir, 'server_private.pem')
        with open(priv_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(key_path, 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        return public_key

def encrypt_data(text, plant_id):
    # Generate AES key
    aes_key = os.urandom(32)  # 256-bit
    iv = os.urandom(12)  # 96-bit for GCM

    # Encrypt data with AES-GCM
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(text.encode()) + encryptor.finalize()

    # Encrypt AES key with RSA
    server_public_key = load_server_public_key()
    encrypted_aes_key = server_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Return as dict or encoded
    return {
        'encrypted_key': base64.b64encode(encrypted_aes_key).decode(),
        'iv': base64.b64encode(iv).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'tag': base64.b64encode(encryptor.tag).decode()
    }
