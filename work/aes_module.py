from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class AESCipher:
    def __init__(self, key: bytes):
        self.key = key[:32]  # AES-256

    def encrypt(self, data: bytes):
        cipher = AES.new(self.key, AES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(data, AES.block_size))
        return cipher.iv, ciphertext

    def decrypt(self, iv: bytes, ciphertext: bytes):
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext
