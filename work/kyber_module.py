import os

class KyberKEM:
    """
    Імітація постквантового алгоритму KEM.
    Генерує випадковий 32-байтовий ключ для AES-256.
    """

    def generate_keypair(self):
        # public_key не використовується, просто для інтерфейсу
        public_key = b"public"
        secret_key = b"secret"
        return public_key, secret_key

    def encapsulate(self, public_key):
        # генеруємо випадковий «спільний секрет»
        shared_secret = os.urandom(32)
        ciphertext = b"ciphertext"  # просто для інтерфейсу
        return ciphertext, shared_secret

    def decapsulate(self, ciphertext, secret_key):
        # генеруємо той самий ключ (для демонстрації беремо випадковий)
        # в реальному PQC це має бути однаковий ключ
        return os.urandom(32)
