from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

def load_private_key(filename="private_key.pem"):
    # Загрузка закрытого ключа из файла
    with open(filename, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )
    return private_key

def decrypt_file(private_key, input_file, output_file="decrypted_file.txt"):
    # Дешифрование файла
    with open(input_file, "rb") as file:
        encrypted_data = file.read()

    decrypted = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open(output_file, "wb") as file:
        file.write(decrypted)

if __name__ == "__main__":
    private_key = load_private_key()

    input_file = "encrypted_file.bin"  # Замените на имя зашифрованного файла
    decrypt_file(private_key, input_file)

    print("Файл успешно дешифрован. Результат сохранен в decrypted_file.txt")