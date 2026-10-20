import time
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

def rsa_10_measurements(iterations=10):
    gen_times = []
    exchange_times = []
    packet_sizes = []
    
    print(f"RSA-2048 için {iterations} adet simülasyon çalıştırılıyor...\n")
    
    for i in range(iterations):
        # --- 1. Anahtar Üretim Süresi Ölçümü (Sunucu Tarafı) ---
        start_gen = time.time()
        server_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        server_public_key = server_private_key.public_key()
        end_gen = time.time()
        
        gen_times.append((end_gen - start_gen) * 1000)
        
        # --- 2. Anahtar Değişim (Şifreleme ve Çözme) Süresi Ölçümü ---
        # İstemci tarafında kullanılacak 16 byte'lık (128-bit) rastgele AES anahtarı
        aes_128_key = os.urandom(16)
        
        start_exchange = time.time()
        # İstemci: AES anahtarını sunucunun açık anahtarı ile şifreler (OAEP Padding ile)
        ciphertext = server_public_key.encrypt(
            aes_128_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Sunucu: Gelen şifreli veriyi (ciphertext) kendi gizli anahtarı ile çözer ve AES anahtarına ulaşır
        decrypted_aes_key = server_private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        end_exchange = time.time()
        
        exchange_times.append((end_exchange - start_exchange) * 1000)
        
        # --- 3. Ağa Giden Paket Boyutu ---
        # Sunucunun ağa gönderdiği açık anahtarın boyutu
        server_public_bytes = server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Toplam ağ trafiği: Sunucunun açık anahtarı + İstemcinin şifreleyip gönderdiği metin (ciphertext)
        total_packet_size = len(server_public_bytes) + len(ciphertext)
        packet_sizes.append(total_packet_size)
        
    # Ortalamaların Hesaplanması
    avg_gen_time = sum(gen_times) / iterations
    avg_exchange_time = sum(exchange_times) / iterations
    avg_packet_size = sum(packet_sizes) / iterations
    
    # Rapor Tablosu Çıktısı
    print("RSA-2048 - 10 Ölçümün Ortalaması")
    print("-" * 50)
    print(f"1. Ortalama Anahtar Üretme Süresi  : {avg_gen_time:.2f} ms")
    print(f"2. Ortalama Anahtar Değişimi Süresi: {avg_exchange_time:.2f} ms")
    print(f"3. Ortalama Ağa Giden Paket Boyutu : {int(avg_packet_size)} byte")
    print("-" * 50)

if __name__ == "__main__":
    rsa_10_measurements()