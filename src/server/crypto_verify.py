from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os

def load_server_private_key():
    keys_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'keys')
    key_path = os.path.join(keys_dir, 'server_private.pem')
    try:
        with open(key_path, 'rb') as f:
            return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    except FileNotFoundError:
        # If not exists, generate (but in client we generate)
        raise Exception("Server private key not found")

def decrypt_data(encrypted_data):
    private_key = load_server_private_key()

    # Decrypt AES key
    encrypted_key = base64.b64decode(encrypted_data['encrypted_key'])
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Decrypt data
    iv = base64.b64decode(encrypted_data['iv'])
    ciphertext = base64.b64decode(encrypted_data['ciphertext'])
    tag = base64.b64decode(encrypted_data['tag'])

    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext.decode()

def load_plant_public_key(plant_id):
    keys_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'keys')
    key_path = os.path.join(keys_dir, f'{plant_id}_public.pem')
    try:
        with open(key_path, 'rb') as f:
            return serialization.load_pem_public_key(f.read(), backend=default_backend())
    except FileNotFoundError:
        raise Exception(f"Public key for {plant_id} not found")

def verify_signature(payload):
    if "data" not in payload or "signature" not in payload or "plant_id" not in payload:
        return False

    plant_id = payload["plant_id"]
    try:
        # Decrypt data
        decrypted_data = decrypt_data(payload["data"])

        # Load public key
        public_key = load_plant_public_key(plant_id)

        # Verify signature
        signature = base64.b64decode(payload["signature"])
        public_key.verify(
            signature,
            decrypted_data.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Verification failed: {e}")
        return False
