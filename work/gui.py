import tkinter as tk
from tkinter import messagebox, filedialog

from kyber_module import KyberKEM
from aes_module import AESCipher


class PQCGui:
    def __init__(self, root):
        self.root = root
        self.root.title("NIST PQC Test System (Kyber + AES)")

        self.kem = KyberKEM()

        self.public_key = None
        self.secret_key = None
        self.ciphertext = None
        self.shared_secret = None

        self.iv = None
        self.encrypted = None

        self.build_ui()

    def build_ui(self):

        tk.Label(self.root, text="Вхідне повідомлення").pack()

        self.input_text = tk.Text(self.root, height=5, width=70)
        self.input_text.pack()

        tk.Button(self.root, text="1. Згенерувати ключі сервера",
                  command=self.generate_keys).pack(pady=4)

        tk.Button(self.root, text="2. Виконати PQC-обмін (Kyber)",
                  command=self.key_exchange).pack(pady=4)

        tk.Button(self.root, text="3. Зашифрувати текст (AES)",
                  command=self.encrypt_message).pack(pady=4)

        tk.Label(self.root, text="Зашифровані дані (hex)").pack()
        self.encrypted_text = tk.Text(self.root, height=5, width=70)
        self.encrypted_text.pack()

        tk.Button(self.root, text="4. Розшифрувати текст",
                  command=self.decrypt_message).pack(pady=4)

        tk.Label(self.root, text="Результат розшифрування").pack()
        self.decrypted_text = tk.Text(self.root, height=5, width=70)
        self.decrypted_text.pack()

        tk.Label(self.root, text="Статус").pack()
        self.status_label = tk.Label(self.root, text="Очікування дій...", fg="blue")
        self.status_label.pack()

        tk.Label(self.root, text="Спільний секрет (AES ключ)").pack()
        self.secret_text = tk.Text(self.root, height=2, width=70)
        self.secret_text.pack()

        tk.Label(self.root, text="--------------------------------").pack(pady=5)

        tk.Button(self.root,
                  text="Зашифрувати файл",
                  command=self.encrypt_file).pack(pady=4)

        tk.Button(self.root,
                  text="Розшифрувати файл",
                  command=self.decrypt_file).pack(pady=4)

    # ================= LOGIC =================
    def generate_keys(self):
        self.public_key, self.secret_key = self.kem.generate_keypair()
        self.shared_secret = None

        self.status_label.config(text="Ключі згенеровано")

        self.secret_text.delete("1.0", tk.END)
        self.secret_text.insert(tk.END, "ще не створено")

        messagebox.showinfo("Готово", "Ключі сервера згенеровано.")

    def key_exchange(self):
        try:
            self.ciphertext, client_secret = self.kem.encapsulate(self.public_key)
            self.shared_secret = client_secret

            self.status_label.config(text="PQC-обмін виконано")

            self.secret_text.delete("1.0", tk.END)
            self.secret_text.insert(tk.END, self.shared_secret.hex())

            messagebox.showinfo("Готово", "PQC-обмін ключами виконано успішно.")

        except Exception as e:
            messagebox.showerror("Помилка", str(e))

    def encrypt_message(self):
        if self.shared_secret is None:
            messagebox.showerror("Помилка", "Спочатку виконайте обмін ключами.")
            return

        text = self.input_text.get("1.0", tk.END).strip()

        aes = AESCipher(self.shared_secret)
        self.iv, self.encrypted = aes.encrypt(text.encode())

        result = self.iv.hex() + self.encrypted.hex()

        self.encrypted_text.delete("1.0", tk.END)
        self.encrypted_text.insert(tk.END, result)

    def decrypt_message(self):
        try:
            aes = AESCipher(self.shared_secret)
            text = aes.decrypt(self.iv, self.encrypted).decode()

            self.decrypted_text.delete("1.0", tk.END)
            self.decrypted_text.insert(tk.END, text)

        except Exception as e:
            messagebox.showerror("Помилка", str(e))

    def encrypt_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return

        with open(file_path, "rb") as f:
            data = f.read()

        aes = AESCipher(self.shared_secret)
        iv, encrypted = aes.encrypt(data)

        save_path = filedialog.asksaveasfilename(defaultextension=".enc")
        if not save_path:
            return

        with open(save_path, "wb") as f:
            f.write(iv + encrypted)

        messagebox.showinfo("Готово", "Файл зашифровано.")

    def decrypt_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return

        with open(file_path, "rb") as f:
            data = f.read()

        iv = data[:16]
        encrypted = data[16:]

        aes = AESCipher(self.shared_secret)
        result = aes.decrypt(iv, encrypted)

        save_path = filedialog.asksaveasfilename()
        if not save_path:
            return

        with open(save_path, "wb") as f:
            f.write(result)

        messagebox.showinfo("Готово", "Файл розшифровано.")


if __name__ == "__main__":
    root = tk.Tk()
    app = PQCGui(root)
    root.mainloop()
