from hashlib import scrypt
import os

def hash_password(password: str) -> str:
    salt = os.urandom(32)
    hashed = scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=64)
    return f"{salt.hex()}:{hashed.hex()}"

def verify_password(password: str, stored_password: str) -> bool:
    try:
        salt_hex, hashed_hex = stored_password.split(":")
        salt = bytes.fromhex(salt_hex)
        hashed = bytes.fromhex(hashed_hex)
        return scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=64) == hashed
    except:
        return False