import os
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES


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


def encryptText(text: bytes, encrypted_sim_key: bytes, private_key, iv: bytes = None):
    """
    Шифрование текста:
    1. Расшифровываем симметричный ключ закрытым ключом RSA
    2. Шифруем текст этим ключом (3DES)
    """
    sim_key = private_key.decrypt(
        encrypted_sim_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    padder = sym_padding.ANSIX923(64).padder()
    padded_text = padder.update(text) + padder.finalize()
    
    if iv is None:
        iv = os.urandom(8)  
    
    
    cipher = Cipher(TripleDES(sim_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    c_text = encryptor.update(padded_text) + encryptor.finalize()
    
    return (c_text, iv)


def decryptText(encrypted_text: bytes, encrypted_sim_key: bytes, private_key, iv: bytes):
    """
    Расшифрование текста:
    1. Расшифровываем симметричный ключ закрытым ключом RSA
    2. Расшифровываем текст симметричным ключом
    """
    
    sim_key = private_key.decrypt(
        encrypted_sim_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    
    cipher = Cipher(TripleDES(sim_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    dc_text = decryptor.update(encrypted_text) + decryptor.finalize()
    
    
    unpadder = sym_padding.ANSIX923(64).unpadder()
    unpadded_dc_text = unpadder.update(dc_text) + unpadder.finalize()
    
    return unpadded_dc_text

def encrypt_text_to_file(text: bytes, encrypted_sim_key: bytes, private_key, output_path: str):
    """
    Шифрование и сохранение в файл: IV + зашифрованный текст
    """
    encrypted_text, iv = encryptText(text, encrypted_sim_key, private_key)
    
    with open(output_path, 'wb') as f:
        f.write(iv)           
        f.write(encrypted_text)  
    
    print(f"Сохранено в {output_path}: IV={iv.hex()}, длина шифротекста={len(encrypted_text)}")


def decrypt_text_from_file(input_path: str, encrypted_sim_key: bytes, private_key) -> bytes:
    """
    Чтение из файла: IV + зашифрованный текст, затем расшифрование
    """
    with open(input_path, 'rb') as f:
        iv = f.read(8)              
        encrypted_text = f.read()   
    
    decrypted_text = decryptText(encrypted_text, encrypted_sim_key, private_key, iv)
    
    return decrypted_text