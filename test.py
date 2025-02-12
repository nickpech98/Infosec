from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  
from cryptography.hazmat.backends import default_backend  
import os  
from cryptography.hazmat.primitives import padding  

# Генерация случайного ключа  
key = os.urandom(32)  
iv = os.urandom(16)  

# Создание объекта шифратора  
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())  
encryptor = cipher.encryptor()  

# Исходный текст  
plaintext = 'Это тестовый текст!'  

# Дополнение текста
padder = padding.PKCS7(algorithms.AES.block_size).padder()  
padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()  

# Шифровка текста  
ciphertext = encryptor.update(padded_data) + encryptor.finalize()  
print("Зашифрованный текст:", ciphertext.hex())  

# Расшифровка текста  
decryptor = cipher.decryptor()  
decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()  

# Удаление дополнения  
unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()  
unpad_data = unpadder.update(decrypted_data) + unpadder.finalize()  
print("Расшифрованный текст:", unpad_data.decode('utf-8'))
