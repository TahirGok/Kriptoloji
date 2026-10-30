import socket
import threading
import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import dh

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

def dinle(s):
    """Sunucudan gelen mesajları sürekli ekrana yazar."""
    try:
        while True:
            data = s.recv(4096)
            if not data:
                print("Sunucu bağlantıyı kapattı.")
                break
            print(data.decode('utf-8'))
    except OSError:
        pass

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    
    # --- RSA El Sıkışma Aşaması ---
    aes_anahtari = client_rsa_handshake(s)
    print(f"[İSTEMCİ] RSA el sıkışması tamamlandı. Ortak AES Anahtarı (Hex): {aes_anahtari.hex()}")
    
    print("Sunucuya bağlanıldı. Çıkmak için 'cikis' yazın.")
    threading.Thread(target=dinle, args=(s,), daemon=True).start()

    try:
        while True:
            mesaj = input()
            if mesaj.strip().lower() == "cikis":
                break
            if mesaj:
                s.sendall(mesaj.encode('utf-8'))
    except (KeyboardInterrupt, EOFError):
        pass