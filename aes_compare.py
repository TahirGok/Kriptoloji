# aes_compare.py
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import aes_manual

# 16 Byte AES-128 Anahtarı ve 16 Byte Test Bloğu
key = b'0123456789abcdef'
data = b'KTU_OF_TEKNO_AES'

# 1. Manuel Kod İle Şifreleme
r_keys = aes_manual.key_expansion(key)
t0 = time.perf_counter()
manual_cipher = aes_manual.encrypt_block(data, r_keys)
t_manual = (time.perf_counter() - t0) * 1000

# 2. Kütüphaneli Kod İle Şifreleme (ECB Modu ile blok doğrulaması)
t0 = time.perf_counter()
cipher = Cipher(algorithms.AES(key), modes.ECB())
encryptor = cipher.encryptor()
lib_cipher = encryptor.update(data) + encryptor.finalize()
t_lib = (time.perf_counter() - t0) * 1000

# 3. Manuel Deşifreleme Testi
decrypted_data = aes_manual.decrypt_block(manual_cipher, r_keys)

print("=" * 60)
print("KTÜ Kriptoloji Projesi - Manuel AES Karşılaştırma Testi")
print("=" * 60)
print(f"Açık Metin        : {data}")
print(f"Manuel Şifreli Hex: {manual_cipher.hex()}")
print(f"Kütüphane Şifreli : {lib_cipher.hex()}")
print(f"Sonuçlar Eşit mi? : {manual_cipher == lib_cipher}")
print(f"Deşifre Başarılı?: {decrypted_data == data}")
print("-" * 60)
print(f"Manuel Şifreleme Süresi    : {t_manual:.4f} ms")
print(f"Kütüphane Şifreleme Süresi : {t_lib:.4f} ms")
print("=" * 60)

if __name__ == "__main__":
    pass