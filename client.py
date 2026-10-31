import socket
import threading
import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import dh
from protokol import TIP_METIN, mesaj_al, mesaj_gonder

HOST = '127.0.0.1'
PORT = 65432

def client_rsa_handshake(sock):
    """Sunucudan gelen açık anahtarı alır, AES anahtarı üretip şifreleyerek geri yollar."""
    public_key_bytes = sock.recv(4096)
    server_public_key = serialization.load_pem_public_key(public_key_bytes)
    
    aes_key = os.urandom(16)
    
    encrypted_aes_key = server_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    sock.sendall(encrypted_aes_key)
    return aes_key

def client_ecc_handshake(sock):
    """Sunucunun açık anahtarını alır, kendi ECC anahtarını gönderir ve ortak sırrı hesaplar."""
    # 1. Sunucunun açık anahtarını alır
    server_pub_bytes = sock.recv(4096)
    server_public_key = serialization.load_pem_public_key(server_pub_bytes)
    
    # 2. İstemci ECC anahtar çiftini üretir
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    
    # 3. Kendi açık anahtarını sunucuya gönderir
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    sock.sendall(public_key_bytes)
    
    # 4. Ortak sırrı hesaplar ve 16 byte AES anahtarı türetir
    shared_key = private_key.exchange(ec.ECDH(), server_public_key)
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)
    
    return aes_key

def client_dh_handshake(sock):
    """Sunucunun parametrelerini alır, kendi DH anahtarını gönderir ve ortak sırrı hesaplar."""
    # 1. Sunucunun açık anahtarını (ve parametrelerini) al
    server_pub_bytes = sock.recv(4096)
    server_public_key = serialization.load_pem_public_key(server_pub_bytes)
    
    # 2. Sunucunun belirlediği DH parametrelerini kullanarak kendi anahtarını üret
    parameters = server_public_key.parameters()
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    
    # 3. Kendi açık anahtarını sunucuya yolla
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    sock.sendall(public_key_bytes)
    
    # 4. Ortak sırrı hesaplar ve 16 byte AES anahtarı türetir
    shared_key = private_key.exchange(server_public_key)
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)
    
    return aes_key

# Seçim tuşu -> (algoritma adı, el sıkışma fonksiyonu). Sunucudaki tuşlarla aynı olmalı.
# Kyber eklendiğinde buraya '4' olarak girilecek.
EL_SIKISMALAR = {
    '1': ("RSA-2048", client_rsa_handshake),
    '2': ("ECC (ECDH)", client_ecc_handshake),
    '3': ("DH-2048", client_dh_handshake),
}


def dinle(s):
    """Sunucudan gelen mesajları sürekli ekrana yazar."""
    try:
        while True:
            cerceve = mesaj_al(s)
            if cerceve is None:
                print("Sunucu bağlantıyı kapattı.")
                break
            tip, veri = cerceve
            if tip == TIP_METIN:
                print(veri.decode('utf-8'))
    except (OSError, ValueError):
        pass

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    # --- Algoritma seçimi ---
    print("Anahtar dağıtım yöntemini seçin:")
    for tus, (ad, _) in EL_SIKISMALAR.items():
        print(f"  {tus} - {ad}")
    while True:
        secim = input("Seçiminiz: ").strip()
        if secim in EL_SIKISMALAR:
            break
        print("Geçersiz seçim, tekrar deneyin.")

    algo_adi, el_sikisma = EL_SIKISMALAR[secim]
    s.sendall(secim.encode())  # sunucuya 1 bayt: seçilen algoritma

    # --- Seçilen algoritmayla el sıkışma ---
    aes_anahtari = el_sikisma(s)
    print(f"[İSTEMCİ] {algo_adi} el sıkışması tamamlandı. Ortak AES Anahtarı (Hex): {aes_anahtari.hex()}")

    print("Sunucuya bağlanıldı. Çıkmak için 'cikis' yazın.")
    threading.Thread(target=dinle, args=(s,), daemon=True).start()

    try:
        while True:
            mesaj = input()
            if mesaj.strip().lower() in ("cikis", "çıkış"):
                break
            if mesaj:
                mesaj_gonder(s, TIP_METIN, mesaj.encode('utf-8'))
    except (KeyboardInterrupt, EOFError):
        pass