import socket
import threading
import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

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