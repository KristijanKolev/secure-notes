import base64

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

DEFAULT_PBKDF2HMAC_ITERATIONS = 480_000
DEFAULT_PBKDF2HMAC_LENGTH = 32
DEFAULT_STRING_ENCODING = 'utf-8'


def generate_password_key(password, salt):
    password_binary = str_to_binary(password)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=DEFAULT_PBKDF2HMAC_LENGTH,
        salt=salt,
        iterations=DEFAULT_PBKDF2HMAC_ITERATIONS,
    )
    password_encryption_key = base64.urlsafe_b64encode(kdf.derive(password_binary))

    return password_encryption_key


def generate_random_key():
    return Fernet.generate_key()


def encrypt_data(data, key=None):
    if key is None:
        key = generate_random_key()

    encryptor = Fernet(key)

    return encryptor.encrypt(data), key


def decrypt_data(data, key):
    encryptor = Fernet(key)
    return encryptor.decrypt(data)


def binary_to_string(data):
    return data.decode(DEFAULT_STRING_ENCODING)


def str_to_binary(data):
    return data.encode(DEFAULT_STRING_ENCODING)
