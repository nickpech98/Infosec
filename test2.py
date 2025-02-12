import rsa

# Генерация пары ключей
(public_key, private_key) = rsa.newkeys(512)

# Исходный текст
message = 'Это тестовый текст'.encode('utf-8')

# Шифровка текста открытым ключом
encrypted_message = rsa.encrypt(message, public_key)
print("Зашифрованный текст:", encrypted_message.hex())

# Расшифровка текста закрытым ключом
decrypted_message = rsa.decrypt(encrypted_message, private_key).decode('utf-8')
print("Расшифрованный текст:", decrypted_message)
