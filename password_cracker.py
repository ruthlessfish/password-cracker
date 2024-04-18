import hashlib
import re

def crack_sha1_hash(hash, use_salts = False):
    pattern = re.compile(r'^[a-fA-F0-9]{40}$')  # Regular expression pattern for SHA1 hash
    if not pattern.match(hash):
        return "INVALID HASH"

    with open('known-salts.txt', 'r') as salts_fd:
        salts = salts_fd.readlines()

    with open('top-10000-passwords.txt', 'r') as passwords:
        for password in passwords:
            password = password.strip()
            if use_salts:
                for salt in salts:
                    salt = salt.strip()
                    if hash_password(password, salt) == hash:
                        return password
                    if hash_password(password, salt, False) == hash:
                        return password
            else:
                if hash_password(password) == hash:
                    return password
    return "PASSWORD NOT IN DATABASE"

def hash_password(password, salt = None, prepend = True):
    if salt is not None:
        password = (salt + password) if prepend else (password + salt)
    return hashlib.sha1(password.encode()).hexdigest()