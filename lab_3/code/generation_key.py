import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


def genSimKey(filePath: str, sizeKey: int, public_key):
    """Генерация и шифрование симметричного ключа"""
    key = os.urandom(sizeKey)
    c_key = public_key.encrypt(
        key, 
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    with open(filePath + "_encrypted_sym.txt", 'wb') as key_file:
        key_file.write(c_key)
    return (key, c_key)  


def genAssimKey(filePath: str):
    """Генерация асимметричных ключей RSA"""
    keys = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    private_key = keys
    public_key = keys.public_key()

    with open(filePath + 'public.pem', 'wb') as public_out:
        public_out.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    with open(filePath + 'private.pem', 'wb') as private_out:
        private_out.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    return (private_key, public_key)
