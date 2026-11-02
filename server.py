import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import dh
from protokol import TIP_METIN, mesaj_al, mesaj_gonder
from sifreleme import aes_sifrele, aes_coz

HOST = '127.0.0.1'
PORT = 65432

clients = {}
clients_lock = threading.Lock()

# Her istemcinin sunucuyla paylaştığı AES-128 anahtarı: {conn: aes_key}
anahtarlar = {}

# DH parametreleri pahalı olduğu için bir kez üretilip tüm bağlantılarda kullanılır
_dh_parametreleri = None
_dh_lock = threading.Lock()


def dh_parametrelerini_al():
    """DH-2048 parametrelerini ilk istekte üretir, sonrakilerde aynısını verir."""
    global _dh_parametreleri
    with _dh_lock:
        if _dh_parametreleri is None:
            print("[SUNUCU] DH-2048 parametreleri üretiliyor (Bu işlem birkaç saniye sürebilir)...")
            _dh_parametreleri = dh.generate_parameters(generator=2, key_size=2048)
        return _dh_parametreleri

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
    # 1. DH Parametreleri (bir kez üretilir) ve bu bağlantıya özel anahtar üretimi
    parameters = dh_parametrelerini_al()
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

# İstemcinin gönderdiği seçim baytı -> (algoritma adı, el sıkışma fonksiyonu)
# Kyber eklendiğinde buraya b'4' olarak girilecek.
EL_SIKISMALAR = {
    b'1': ("RSA-2048", server_rsa_handshake),
    b'2': ("ECC (ECDH)", server_ecc_handshake),
    b'3': ("DH-2048", server_dh_handshake),
}


def yonlendir(gonderen_conn, tip, duz_veri):
    """Düz (çözülmüş) veriyi, her alıcının KENDİ AES anahtarıyla yeniden şifreleyip iletir.

    Henüz el sıkışması süren bir istemciye mesaj gönderilmez, aksi halde
    el sıkışma baytlarıyla karışırdı. clients_lock tutulduğu için aynı soketa
    aynı anda iki thread yazamaz, çerçeveler iç içe geçmez.
    """
    with clients_lock:
        for conn, alici_anahtari in list(anahtarlar.items()):
            if conn is gonderen_conn:
                continue
            try:
                mesaj_gonder(conn, tip, aes_sifrele(alici_anahtari, duz_veri))
            except OSError:
                pass

def istemci_yonet(conn, addr, no):
    """Her istemci için ayrı thread'de çalışır."""
    print(f"Bağlantı sağlandı: İstemci {no} {addr}")
    try:
        # --- Algoritma seçimi: istemci ilk olarak 1 bayt gönderir ---
        secim = conn.recv(1)
        if secim not in EL_SIKISMALAR:
            print(f"[SUNUCU] İstemci {no} geçersiz algoritma seçti: {secim!r}")
            return
        algo_adi, el_sikisma = EL_SIKISMALAR[secim]

        # --- Seçilen algoritmayla el sıkışma ---
        aes_anahtari = el_sikisma(conn)
        with clients_lock:
            anahtarlar[conn] = aes_anahtari
        print(f"[SUNUCU] İstemci {no} ile {algo_adi} el sıkışması tamamlandı. Ortak AES (Hex): {aes_anahtari.hex()}")

        while True:
            cerceve = mesaj_al(conn)
            if cerceve is None:
                break
            tip, veri = cerceve
            if tip == TIP_METIN:
                # 1) Gönderenin anahtarıyla çöz
                try:
                    mesaj = aes_coz(aes_anahtari, veri).decode('utf-8')
                except ValueError:  # UnicodeDecodeError de ValueError'dır
                    print(f"[SUNUCU] İstemci {no}: mesaj çözülemedi (bozuk veri ya da yanlış anahtar), atlandı.")
                    continue
                print(f"İstemci {no} -> diğerlerine: {mesaj}  (gelen şifreli paket: {len(veri)} bayt)")
                # 2) Her alıcının kendi anahtarıyla yeniden şifreleyip ilet
                yonlendir(conn, TIP_METIN, f"[İstemci {no}] {mesaj}".encode('utf-8'))
            else:
                print(f"[SUNUCU] İstemci {no} bilinmeyen mesaj türü gönderdi: {tip!r}")
    except ConnectionError:
        pass
    except Exception as e:
        print(f"[SUNUCU] İstemci {no} ile hata: {e}")
    finally:
        with clients_lock:
            clients.pop(conn, None)
            anahtarlar.pop(conn, None)
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