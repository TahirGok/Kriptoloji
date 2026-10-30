import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import dh

HOST = '127.0.0.1'
PORT = 65432

clients = {}
clients_lock = threading.Lock()

def yeni_istemci_no():
    """Kullanılmayan en küçük istemci numarasını verir (1, 2, 3...)."""
    no = 1
    while no in clients.values():
        no += 1
    return no

def server_rsa_handshake(conn):
    """Bu bağlantıya özel anahtar çifti üretir ve istemciden gelen şifreli AES anahtarını çözer."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    conn.sendall(public_key_bytes)
    
    encrypted_aes_key = conn.recv(4096)
    
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key

def server_ecc_handshake(conn):
    """Sunucu için ECC anahtar çifti üretir, açık anahtarı gönderir ve ortak sırrı hesaplar."""
    # 1. Sunucu ECC anahtar çiftini üretir
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    
    # 2. Açık anahtarı istemciye gönderir
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    conn.sendall(public_key_bytes)
    
    # 3. İstemcinin açık anahtarını alır
    client_pub_bytes = conn.recv(4096)
    client_public_key = serialization.load_pem_public_key(client_pub_bytes)
    
    # 4. Ortak sırrı hesaplar ve 16 byte AES anahtarı türetir
    shared_key = private_key.exchange(ec.ECDH(), client_public_key)
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)
    
    return aes_key

def server_dh_handshake(conn):
    """Sunucu için DH-2048 anahtar çifti üretir, açık anahtarı gönderir ve ortak sırrı hesaplar."""
    print("[SUNUCU] DH-2048 parametreleri üretiliyor (Bu işlem birkaç saniye sürebilir)...")
    
    # 1. DH Parametreleri ve anahtar üretimi
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    
    # 2. Açık anahtarı (ve içindeki parametreleri) istemciye gönder
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    conn.sendall(public_key_bytes)
    
    # 3. İstemcinin açık anahtarını al
    client_pub_bytes = conn.recv(4096)
    client_public_key = serialization.load_pem_public_key(client_pub_bytes)
    
    # 4. Ortak sırrı hesaplar ve 16 byte AES anahtarı türetir
    shared_key = private_key.exchange(client_public_key)
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)
    
    return aes_key

def yonlendir(gonderen_conn, veri):
    """Gelen mesajı gönderen hariç tüm istemcilere iletir."""
    with clients_lock:
        for conn in list(clients):
            if conn is gonderen_conn:
                continue
            try:
                conn.sendall(veri)
            except OSError:
                pass  

def istemci_yonet(conn, addr, no):
    """Her istemci için ayrı thread'de çalışır."""
    print(f"Bağlantı sağlandı: İstemci {no} {addr}")
    try:
        # --- RSA El Sıkışma Aşaması ---
        aes_anahtari = server_rsa_handshake(conn)
        print(f"[SUNUCU] İstemci {no} ile RSA el sıkışması tamamlandı. Ortak AES (Hex): {aes_anahtari.hex()}")
        
        while True:
            data = conn.recv(4096)
            if not data:
                break
            mesaj = data.decode('utf-8')
            print(f"İstemci {no} -> diğerlerine: {mesaj}")
            yonlendir(conn, f"[İstemci {no}] {mesaj}".encode('utf-8'))
    except ConnectionError:
        pass
    finally:
        with clients_lock:
            clients.pop(conn, None)
        conn.close()
        print(f"İstemci {no} ayrıldı.")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen()
    print(f"Sunucu {HOST}:{PORT} adresinde dinleniyor...")

    try:
        while True:
            conn, addr = s.accept()
            with clients_lock:
                no = yeni_istemci_no()
                clients[conn] = no
            threading.Thread(
                target=istemci_yonet, args=(conn, addr, no), daemon=True
            ).start()
    except KeyboardInterrupt:
        print("\nSunucu kapatılıyor...")