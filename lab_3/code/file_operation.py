from sym_encrypt import encryptText, decryptText
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