# aes_compare.py
import argparse
import os
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import aes_manual


def main():
    parser = argparse.ArgumentParser(
        description="Manuel AES ile kütüphane AES'ini karşılaştırır.",
        epilog="CBC eğitim amaçlıdır ve kimlik doğrulama sağlamaz; gerçek uygulamalarda AEAD kullanın.",
    )
    parser.add_argument(
        "--text",
        default="KTU_OF_TEKNO_AES",
        help="Karşılaştırılacak metin (varsayılan: KTU_OF_TEKNO_AES)",
    )
    parser.add_argument(
        "--key",
        default="0123456789abcdef",
        help="AES-128 için 16 baytlık anahtar (varsayılan: 0123456789abcdef)",
    )
    parser.add_argument(
        "--mode",
        choices=("ecb", "cbc"),
        default="ecb",
        help="AES çalışma modu (varsayılan: ecb)",
    )
    parser.add_argument(
        "--iv",
        help="CBC için 32 karakterlik hex IV (verilmezse rastgele üretilir)",
    )
    args = parser.parse_args()
    data = args.text.encode("utf-8")
    if args.mode == "ecb" and len(data) != 16:
        parser.error(f"ECB testi için metin UTF-8 olarak tam 16 bayt olmalı; girilen: {len(data)} bayt.")
    key = args.key.encode("utf-8")
    if len(key) != 16:
        parser.error(f"Anahtar UTF-8 olarak tam 16 bayt olmalı; girilen: {len(key)} bayt.")
    if args.mode == "ecb" and args.iv:
        parser.error("--iv yalnızca CBC modunda kullanılabilir.")

    iv = None
    if args.mode == "cbc":
        try:
            iv = bytes.fromhex(args.iv) if args.iv else os.urandom(16)
        except ValueError:
            parser.error("IV hex biçiminde olmalıdır.")
        if len(iv) != 16:
            parser.error(f"CBC IV değeri tam 16 bayt (32 hex karakter) olmalıdır; girilen: {len(iv)} bayt.")

    r_keys = aes_manual.key_expansion(key)
    mode = modes.ECB() if args.mode == "ecb" else modes.CBC(iv)
    if args.mode == "cbc":
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        library_input = padder.update(data) + padder.finalize()
    else:
        library_input = data

    # 1. Manuel Kod İle Şifreleme
    t0 = time.perf_counter()
    if args.mode == "cbc":
        manual_cipher = aes_manual.encrypt_cbc(data, r_keys, iv)
    else:
        manual_cipher = aes_manual.encrypt_block(data, r_keys)
    t_manual = (time.perf_counter() - t0) * 1000

    # 2. Kütüphaneli Kod İle Şifreleme
    t0 = time.perf_counter()
    cipher = Cipher(algorithms.AES(key), mode)
    encryptor = cipher.encryptor()
    lib_cipher = encryptor.update(library_input) + encryptor.finalize()
    t_lib = (time.perf_counter() - t0) * 1000

    # 3. Manuel Deşifreleme Testi
    if args.mode == "cbc":
        decrypted_data = aes_manual.decrypt_cbc(manual_cipher, r_keys, iv)
    else:
        decrypted_data = aes_manual.decrypt_block(manual_cipher, r_keys)

    # 4. Kütüphane ile manuel şifreli veriyi çözme testi
    decryptor = Cipher(algorithms.AES(key), mode).decryptor()
    lib_decrypted_data = decryptor.update(manual_cipher) + decryptor.finalize()
    if args.mode == "cbc":
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        lib_decrypted_data = unpadder.update(lib_decrypted_data) + unpadder.finalize()

    print("=" * 60)
    print("KTÜ Kriptoloji Projesi - Manuel AES Karşılaştırma Testi")
    print("=" * 60)
    print(f"Mod               : {args.mode.upper()}")
    if iv is not None:
        print(f"IV                : {iv.hex()}")
    print(f"Açık Metin        : {args.text}")
    print(f"Manuel Şifreli Hex: {manual_cipher.hex()}")
    print(f"Kütüphane Şifreli : {lib_cipher.hex()}")
    print(f"Sonuçlar Eşit mi? : {manual_cipher == lib_cipher}")
    print(f"Deşifre Başarılı?: {decrypted_data == data}")
    print(f"Kütüphane Deşifre Başarılı?: {lib_decrypted_data == data}")
    print("-" * 60)
    print(f"Manuel Şifreleme Süresi    : {t_manual:.4f} ms")
    print(f"Kütüphane Şifreleme Süresi : {t_lib:.4f} ms")
    print("=" * 60)


if __name__ == "__main__":
    main()