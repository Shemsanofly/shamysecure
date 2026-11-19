# crypto_utils.py
# All the cryptography of the project: RSA, ChaCha20, SHA-256

import os
import hashlib
import getpass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.exceptions import InvalidSignature

RSA_KEY_SIZE = 2048
RSA_PUBLIC_EXPONENT = 65537
CHACHA_KEY_SIZE = 32        # 256 bit key
CHACHA_NONCE_SIZE = 12      # 96 bit nonce (RFC 7539)
CHALLENGE_SIZE = 32         # random bytes used in the handshake
HASH_READ_SIZE = 64 * 1024

PRIVATE_KEY_FILE = "private_key.pem"
PUBLIC_KEY_FILE = "public_key.pem"


# ---------------- RSA key pair ----------------

def generate_rsa_keys():
    print("[*] Generating new RSA-2048 key pair, please wait...")
    private_key = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT,
        key_size=RSA_KEY_SIZE,
    )
    return private_key


def save_rsa_keys(private_key, keys_folder, password=None):
    os.makedirs(keys_folder, exist_ok=True)

    # private key can be protected with a password
    if password:
        encryption = serialization.BestAvailableEncryption(password.encode())
    else:
        encryption = serialization.NoEncryption()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    public_pem = public_key_to_bytes(private_key.public_key())

    private_path = os.path.join(keys_folder, PRIVATE_KEY_FILE)
    public_path = os.path.join(keys_folder, PUBLIC_KEY_FILE)

    with open(private_path, "wb") as f:
        f.write(private_pem)
    with open(public_path, "wb") as f:
        f.write(public_pem)

    # only the owner should read the private key (no effect on Windows)
    try:
        os.chmod(private_path, 0o600)
    except OSError:
        pass

    print("[*] Keys saved in folder:", keys_folder)


def load_rsa_keys(keys_folder):
    private_path = os.path.join(keys_folder, PRIVATE_KEY_FILE)
    with open(private_path, "rb") as f:
        data = f.read()

    # first try without password
    try:
        return serialization.load_pem_private_key(data, password=None)
    except TypeError:
        pass  # key is password protected

    for attempt in range(3):
        password = getpass.getpass("Enter password for private key: ")
        try:
            return serialization.load_pem_private_key(data, password=password.encode())
        except ValueError:
            print("[!] Wrong password")

    raise SystemExit("[!] Could not unlock private key")


def load_or_create_rsa_keys(keys_folder, use_password=False):
    private_path = os.path.join(keys_folder, PRIVATE_KEY_FILE)

    if os.path.exists(private_path):
        private_key = load_rsa_keys(keys_folder)
        print("[*] Loaded RSA key pair from:", keys_folder)
        return private_key

    private_key = generate_rsa_keys()

    password = None
    if use_password:
        while True:
            password = getpass.getpass("Choose a password for the private key: ")
            again = getpass.getpass("Repeat password: ")
            if password and password == again:
                break
            print("[!] Passwords do not match or empty, try again")

    save_rsa_keys(private_key, keys_folder, password)
    return private_key


# ---------------- public key helpers ----------------

def public_key_to_bytes(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def public_key_to_text(public_key):
    return public_key_to_bytes(public_key).decode()


def public_key_from_text(pem_text):
    key = serialization.load_pem_public_key(pem_text.encode())
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("not an RSA public key")
    if key.key_size < RSA_KEY_SIZE:
        raise ValueError("RSA key is too small")
    return key


def get_fingerprint(public_key):
    # SHA-256 of the public key, first 16 bytes shown as AA:BB:CC...
    digest = hashlib.sha256(public_key_to_bytes(public_key)).hexdigest().upper()
    pairs = [digest[i:i + 2] for i in range(0, 32, 2)]
    return ":".join(pairs)


# ---------------- RSA-OAEP (encrypt the file key) ----------------

def _oaep():
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def rsa_encrypt(receiver_public_key, data):
    # only the receiver's private key can open this
    return receiver_public_key.encrypt(data, _oaep())


def rsa_decrypt(my_private_key, encrypted_data):
    return my_private_key.decrypt(encrypted_data, _oaep())


# ---------------- RSA-PSS (signatures) ----------------

def _pss():
    return padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH,
    )


def rsa_sign(my_private_key, data):
    return my_private_key.sign(data, _pss(), hashes.SHA256())


def rsa_verify(sender_public_key, signature, data):
    try:
        sender_public_key.verify(signature, data, _pss(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False


# ---------------- handshake challenge ----------------

def new_challenge():
    return os.urandom(CHALLENGE_SIZE)


def sign_challenge(my_private_key, challenge, my_public_key_text):
    # bind the challenge to our own public key
    data = b"HANDSHAKE" + challenge + my_public_key_text.encode()
    return rsa_sign(my_private_key, data)


def verify_challenge(peer_public_key, signature, challenge, peer_public_key_text):
    data = b"HANDSHAKE" + challenge + peer_public_key_text.encode()
    return rsa_verify(peer_public_key, signature, data)


# ---------------- ChaCha20 ----------------

def new_file_key():
    # fresh random key for EVERY file
    return os.urandom(CHACHA_KEY_SIZE)


def new_nonce():
    return os.urandom(CHACHA_NONCE_SIZE)


def _full_nonce(nonce):
    # the library wants 16 bytes: 4 byte block counter (start at 0) + 12 byte nonce
    counter = (0).to_bytes(4, "little")
    return counter + nonce


def chacha20_encryptor(key, nonce):
    cipher = Cipher(algorithms.ChaCha20(key, _full_nonce(nonce)), mode=None)
    return cipher.encryptor()


def chacha20_decryptor(key, nonce):
    cipher = Cipher(algorithms.ChaCha20(key, _full_nonce(nonce)), mode=None)
    return cipher.decryptor()


# ---------------- hashing ----------------

def sha256_of_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            block = f.read(HASH_READ_SIZE)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


class TransferHasher:
    # hashes everything that the signature must protect

    def __init__(self, transfer_id, filename, size, encrypted_key, nonce):
        self.h = hashlib.sha256()
        self.h.update(b"FILE")
        self.h.update(transfer_id.encode())
        self.h.update(filename.encode())
        self.h.update(str(size).encode())
        self.h.update(encrypted_key)
        self.h.update(nonce)

    def add_chunk(self, ciphertext_chunk):
        self.h.update(ciphertext_chunk)

    def digest(self):
        return self.h.digest()
