from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

def generate_keys():
    # Генерация пары ключей
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_private_key(private_key, filename="private_key.pem"):
    # Сохранение закрытого ключа в файл
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filename, "wb") as key_file:
        key_file.write(pem)

def encrypt_file(public_key, input_file, output_file="encrypted_file.bin"):
    # Шифрование файла
    with open(input_file, "rb") as file:
        file_data = file.read()

    encrypted = public_key.encrypt(
        file_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open(output_file, "wb") as file:
        file.write(encrypted)

if __name__ == "__main__":
    private_key, public_key = generate_keys()
    save_private_key(private_key)

    input_file = "input.txt"  # Замените на имя вашего файла
    encrypt_file(public_key, input_file)

    print("Файл успешно зашифрован. Закрытый ключ сохранен в private_key.pem")