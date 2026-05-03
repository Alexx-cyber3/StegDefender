import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

class CryptoManager:
    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    @staticmethod
    def encrypt_aes(data: bytes, password: str) -> str:
        salt = os.urandom(16)
        key = CryptoManager._derive_key(password, salt)
        iv = os.urandom(12) # GCM recommended IV length
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        # Format: salt(16) + iv(12) + tag(16) + ciphertext
        result = salt + iv + encryptor.tag + ciphertext
        return result.hex()

    @staticmethod
    def decrypt_aes(token: str, password: str) -> bytes:
        try:
            raw = bytes.fromhex(token)
            salt = raw[:16]
            iv = raw[16:28]
            tag = raw[28:44]
            ciphertext = raw[44:]
            
            key = CryptoManager._derive_key(password, salt)
            
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            return decryptor.update(ciphertext) + decryptor.finalize()
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")

    @staticmethod
    def encrypt_chacha(data: bytes, password: str) -> str:
        salt = os.urandom(16)
        key = CryptoManager._derive_key(password, salt)
        nonce = os.urandom(16)
        
        algorithm = algorithms.ChaCha20(key, nonce)
        cipher = Cipher(algorithm, mode=None, backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data)
        
        # Format: salt(16) + nonce(16) + ciphertext
        result = salt + nonce + ciphertext
        return result.hex()

    @staticmethod
    def decrypt_chacha(token: str, password: str) -> bytes:
        try:
            raw = bytes.fromhex(token)
            salt = raw[:16]
            nonce = raw[16:32]
            ciphertext = raw[32:]
            
            key = CryptoManager._derive_key(password, salt)
            
            algorithm = algorithms.ChaCha20(key, nonce)
            cipher = Cipher(algorithm, mode=None, backend=default_backend())
            decryptor = cipher.decryptor()
            return decryptor.update(ciphertext)
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")

    @staticmethod
    def generate_rsa_keys():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return priv_pem.decode(), pub_pem.decode()

    @staticmethod
    def encrypt_rsa(data: bytes, public_key_pem: str) -> str:
        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode(),
                backend=default_backend()
            )
            
            ciphertext = public_key.encrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return ciphertext.hex()
        except Exception as e:
            raise ValueError(f"RSA Encryption failed: {str(e)}")

    @staticmethod
    def decrypt_rsa(token: str, private_key_pem: str) -> bytes:
        try:
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                password=None,
                backend=default_backend()
            )
            
            ciphertext = bytes.fromhex(token)
            
            plaintext = private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return plaintext
        except Exception as e:
            raise ValueError(f"RSA Decryption failed: {str(e)}")

    @staticmethod
    def hash_sha256(data: bytes) -> str:
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(data)
        return digest.finalize().hex()