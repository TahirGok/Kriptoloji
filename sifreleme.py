"""AES-128-CBC ile mesaj şifreleme / çözme.

Şifreli paket biçimi:   IV (16 bayt) + şifreli veri

- Her mesaj için rastgele yeni bir IV üretilir (aynı mesaj iki kez gitse bile
  şifreli hali farklı olur).
- Veri PKCS7 ile 16 baytın katına tamamlanır (padding).
- Şu an kütüphaneli (cryptography) AES kullanılıyor. Kadir'in manuel AES'i
  (aes_manual.encrypt_cbc / decrypt_cbc) aynı biçimi üretecek şekilde buraya
  takılabilir: sadece aşağıdaki iki fonksiyonun içi değişir.

Not: CBC tek başına veri bütünlüğünü doğrulamaz (araya giren biri şifreli veriyi
bozabilir). Bu projede istenen AES-128 + CBC olduğu için bütünlük doğrulaması
(HMAC / GCM) eklenmedi.
"""
import os

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

IV_BOYUTU = 16


def aes_sifrele(anahtar, veri):
    """veri (bytes) -> IV + şifreli veri (bytes). anahtar 16 bayt olmalı."""
    iv = os.urandom(IV_BOYUTU)
    dolgulu = padding.PKCS7(128).padder()
    dolgulu_veri = dolgulu.update(veri) + dolgulu.finalize()
    sifreleyici = Cipher(algorithms.AES(anahtar), modes.CBC(iv)).encryptor()
    return iv + sifreleyici.update(dolgulu_veri) + sifreleyici.finalize()


def aes_coz(anahtar, paket):
    """IV + şifreli veri -> düz veri. Paket bozuksa ya da anahtar yanlışsa ValueError verir."""
    if len(paket) < IV_BOYUTU + 16 or (len(paket) - IV_BOYUTU) % 16 != 0:
        raise ValueError("Şifreli paket geçersiz uzunlukta.")
    iv, sifreli = paket[:IV_BOYUTU], paket[IV_BOYUTU:]
    cozucu = Cipher(algorithms.AES(anahtar), modes.CBC(iv)).decryptor()
    dolgulu_veri = cozucu.update(sifreli) + cozucu.finalize()
    dolgu_kaldir = padding.PKCS7(128).unpadder()
    return dolgu_kaldir.update(dolgulu_veri) + dolgu_kaldir.finalize()