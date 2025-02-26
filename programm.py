import tkinter as tk
from tkinter import filedialog, messagebox
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

def select_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        entry_file.delete(0, tk.END)
        entry_file.insert(0, file_path)

def encrypt_selected_file():
    input_file = entry_file.get()
    if not input_file:
        messagebox.showerror("Ошибка", "Пожалуйста, выберите файл для шифрования")
        return

    private_key, public_key = generate_keys()
    save_private_key(private_key)

    output_file = "encrypted_file.bin"
    encrypt_file(public_key, input_file, output_file)

    messagebox.showinfo("Успех", f"Файл успешно зашифрован и сохранен как {output_file}\nЗакрытый ключ сохранен как private_key.pem")

# Создание основного окна
root = tk.Tk()
root.title("Шифратор файлов")

# Создание и размещение элементов интерфейса
label_file = tk.Label(root, text="Выберите файл для шифрования:")
label_file.grid(row=0, column=0, padx=10, pady=10)

entry_file = tk.Entry(root, width=50)
entry_file.grid(row=0, column=1, padx=10, pady=10)

button_browse = tk.Button(root, text="Обзор", command=select_file)
button_browse.grid(row=0, column=2, padx=10, pady=10)

button_encrypt = tk.Button(root, text="Зашифровать", command=encrypt_selected_file)
button_encrypt.grid(row=1, column=1, padx=10, pady=10)

# Запуск основного цикла обработки событий
root.mainloop()