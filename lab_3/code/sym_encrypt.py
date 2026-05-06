import os
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES

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

