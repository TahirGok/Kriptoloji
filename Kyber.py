import time
try:
    import oqs
except ImportError:
    print("Lütfen önce kütüphaneyi kurun: pip install liboqs-python")
    exit()

def kyber_10_measurements(iterations=10):
    # Standartlaşmış ML-KEM-768 veya kütüphanedeki eski adıyla Kyber768
    kem_name = "ML-KEM-768"
    if kem_name not in oqs.get_enabled_kem_mechanisms():
        kem_name = "Kyber768"
        
    gen_times = []
    exchange_times = []
    packet_sizes = []
    
    print(f"Kyber ({kem_name}) için {iterations} adet simülasyon çalıştırılıyor...\n")
    
    for i in range(iterations):
        with oqs.KeyEncapsulation(kem_name) as kem:
            # --- 1. Anahtar Üretim Süresi Ölçümü (Sunucu tarafı) ---
            start_gen = time.time()
            public_key = kem.generate_keypair()
            end_gen = time.time()
            
            gen_times.append((end_gen - start_gen) * 1000)
            
            # --- 2. Anahtar Değişim Süresi Ölçümü (Kapsülleme + Kapsül Açma) ---
            start_exchange = time.time()
            
            # İstemci: Açık anahtarı kullanarak ortak sırrı kapsüller (encapsulate)
            ciphertext, shared_secret_client = kem.encap_secret(public_key)
            
            # Sunucu: Gelen ciphertext'i açarak ortak sırrı elde eder (decapsulate)
            shared_secret_server = kem.decap_secret(ciphertext)
            
            end_exchange = time.time()
            
            exchange_times.append((end_exchange - start_exchange) * 1000)
            
            # --- 3. Ağa Giden Paket Boyutu ---
            # Toplam ağ trafiği: Sunucunun açık anahtarı + İstemcinin ciphertext'i
            total_bytes_exchanged = len(public_key) + len(ciphertext)
            packet_sizes.append(total_bytes_exchanged)
            
    # Ortalamaların Hesaplanması
    avg_gen_time = sum(gen_times) / iterations
    avg_exchange_time = sum(exchange_times) / iterations
    avg_packet_size = sum(packet_sizes) / iterations
    
    # Rapor Tablosu Çıktısı
    print("Kyber (ML-KEM-768) - 10 Ölçümün Ortalaması")
    print("-" * 50)
    print(f"1. Ortalama Anahtar Üretme Süresi  : {avg_gen_time:.2f} ms")
    print(f"2. Ortalama Anahtar Değişimi Süresi: {avg_exchange_time:.2f} ms")
    print(f"3. Ortalama Ağa Giden Paket Boyutu : {int(avg_packet_size)} byte")
    print("-" * 50)

if __name__ == "__main__":
    kyber_10_measurements()