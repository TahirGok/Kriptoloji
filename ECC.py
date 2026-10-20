import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def ecc_10_measurements(iterations=10):
    gen_times = []
    exchange_times = []
    packet_sizes = []
    
    print(f"ECC (ECDH) için {iterations} adet simülasyon çalıştırılıyor...\n")
    
    for i in range(iterations):
        # --- 1. Anahtar Üretim Süresi Ölçümü ---
        start_gen = time.time()
        # SECP256R1 (NIST P-256) eğrisi kullanılarak anahtar üretimi
        alice_private_key = ec.generate_private_key(ec.SECP256R1())
        alice_public_key = alice_private_key.public_key()
        
        # Açık anahtarı byte formatına çevir (Ağa gidecek paket)
        alice_public_bytes = alice_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        end_gen = time.time()
        
        gen_times.append((end_gen - start_gen) * 1000)
        packet_sizes.append(len(alice_public_bytes))
        
        # Bob için simüle edilmiş anahtar
        bob_private_key = ec.generate_private_key(ec.SECP256R1())
        bob_public_key = bob_private_key.public_key()
        
        # --- 2. Anahtar Değişim Süresi Ölçümü ---
        start_exchange = time.time()
        # Alice, Bob'un açık anahtarını alıp ortak sırrı hesaplar
        shared_key = alice_private_key.exchange(ec.ECDH(), bob_public_key)
        
        # Ortak sırrın 16 byte'lık AES-128 anahtarına dönüştürülmesi
        aes_128_key = HKDF(
            algorithm=hashes.SHA256(),
            length=16,
            salt=None,
            info=b'handshake data',
        ).derive(shared_key)
        end_exchange = time.time()
        
        exchange_times.append((end_exchange - start_exchange) * 1000)
    
    # Ortalamaların Hesaplanması
    avg_gen_time = sum(gen_times) / iterations
    avg_exchange_time = sum(exchange_times) / iterations
    avg_packet_size = sum(packet_sizes) / iterations
    
    # Rapor Tablosu Çıktısı
    print("ECC (ECDH) - 10 Ölçümün Ortalaması")
    print("-" * 50)
    print(f"1. Ortalama Anahtar Üretme Süresi  : {avg_gen_time:.2f} ms")
    print(f"2. Ortalama Anahtar Değişimi Süresi: {avg_exchange_time:.2f} ms")
    print(f"3. Ortalama Ağa Giden Paket Boyutu : {int(avg_packet_size)} byte")
    print("-" * 50)

if __name__ == "__main__":
    ecc_10_measurements()