import tkinter as tk
from tkinter import messagebox, filedialog
import os

from kyber_module import KyberKEM
from aes_module import AESCipher

class PQCGui:
    def __init__(self, root):
        self.root = root
        self.root.title("Тестова система шифрування (імітація PQC + AES)")

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

        tk.Button(self.root, text="1. Згенерувати ключі сервера", command=self.generate_keys).pack(pady=4)
        tk.Button(self.root, text="2. Виконати PQC-обмін (імітація)", command=self.key_exchange).pack(pady=4)
        tk.Button(self.root, text="3. Зашифрувати текст (AES)", command=self.encrypt_message).pack(pady=4)

        tk.Label(self.root, text="Зашифровані дані (hex)").pack()
        self.encrypted_text = tk.Text(self.root, height=5, width=70)
        self.encrypted_text.pack()

        tk.Button(self.root, text="4. Розшифрувати текст", command=self.decrypt_message).pack(pady=4)

        tk.Label(self.root, text="Результат розшифрування").pack()
        self.decrypted_text = tk.Text(self.root, height=5, width=70)
        self.decrypted_text.pack()

        tk.Label(self.root, text="-----------------------------------------").pack(pady=5)

        tk.Button(self.root, text="Зашифрувати файл (PDF, DOCX, будь-який)", command=self.encrypt_file).pack(pady=4)
        tk.Button(self.root, text="Розшифрувати файл", command=self.decrypt_file).pack(pady=4)

    # ======================== кнопки =========================
    def generate_keys(self):
        self.public_key, self.secret_key = self.kem.generate_keypair()
        self.shared_secret = None
        messagebox.showinfo("Готово", "Ключі сервера згенеровано.")

    def key_exchange(self):
        try:
            self.ciphertext, self.shared_secret = self.kem.encapsulate(self.public_key)
            messagebox.showinfo("Готово", "PQC-обмін ключами виконано успішно (імітація).")
        except Exception as e:
            messagebox.showerror("Помилка обміну", str(e))

    def encrypt_message(self):
        if self.shared_secret is None:
            messagebox.showerror("Помилка", "Спочатку виконайте обмін ключами.")
            return

        text = self.input_text.get("1.0", tk.END).strip()
        if not text:
            messagebox.showerror("Помилка", "Введіть повідомлення.")
            return

        aes = AESCipher(self.shared_secret)
        self.iv, self.encrypted = aes.encrypt(text.encode("utf-8"))

        result_hex = self.iv.hex() + self.encrypted.hex()
        self.encrypted_text.delete("1.0", tk.END)
        self.encrypted_text.insert(tk.END, result_hex)

    def decrypt_message(self):
        if self.shared_secret is None or self.iv is None:
            messagebox.showerror("Помилка", "Немає даних для розшифрування.")
            return

        try:
            aes = AESCipher(self.shared_secret)
            decrypted = aes.decrypt(self.iv, self.encrypted)
            self.decrypted_text.delete("1.0", tk.END)
            self.decrypted_text.insert(tk.END, decrypted.decode("utf-8"))
        except Exception as e:
            messagebox.showerror("Помилка", str(e))

    # ======================== файли =========================
    def encrypt_file(self):
        if self.shared_secret is None:
            messagebox.showerror("Помилка", "Спочатку виконайте обмін ключами.")
            return

        file_path = filedialog.askopenfilename()
        if not file_path:
            return

        with open(file_path, "rb") as f:
            data = f.read()

        aes = AESCipher(self.shared_secret)
        iv, encrypted = aes.encrypt(data)

        save_path = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[("Encrypted file", "*.enc")])
        if not save_path:
            return

        with open(save_path, "wb") as f:
            f.write(iv + encrypted)

        messagebox.showinfo("Готово", "Файл успішно зашифровано.")

    def decrypt_file(self):
        if self.shared_secret is None:
            messagebox.showerror("Помилка", "Спочатку виконайте обмін ключами.")
            return

        file_path = filedialog.askopenfilename(filetypes=[("Encrypted file", "*.enc")])
        if not file_path:
            return

        with open(file_path, "rb") as f:
            raw = f.read()

        iv = raw[:16]
        ciphertext = raw[16:]

        try:
            aes = AESCipher(self.shared_secret)
            data = aes.decrypt(iv, ciphertext)
        except Exception as e:
            messagebox.showerror("Помилка", "Не вдалося розшифрувати файл.")
            return

        save_path = filedialog.asksaveasfilename()
        if not save_path:
            return

        with open(save_path, "wb") as f:
            f.write(data)

        messagebox.showinfo("Готово", "Файл успішно розшифровано.")


if __name__ == "__main__":
    root = tk.Tk()
    app = PQCGui(root)
    root.mainloop()
