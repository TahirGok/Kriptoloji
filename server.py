import socket
import threading

HOST = '127.0.0.1'
PORT = 65432

# Bağlı istemciler: {conn: istemci_no}
clients = {}
clients_lock = threading.Lock()


def yeni_istemci_no():
    """Kullanılmayan en küçük istemci numarasını verir (1, 2, 3...)."""
    no = 1
    while no in clients.values():
        no += 1
    return no


def yonlendir(gonderen_conn, veri):
    """Gelen mesajı gönderen hariç tüm istemcilere iletir."""
    with clients_lock:
        for conn in list(clients):
            if conn is gonderen_conn:
                continue
            try:
                conn.sendall(veri)
            except OSError:
                pass  # Bağlantısı kopmuş istemciyi kendi thread'i temizleyecek


def istemci_yonet(conn, addr, no):
    """Her istemci için ayrı thread'de çalışır."""
    print(f"Bağlantı sağlandı: İstemci {no} {addr}")
    try:
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