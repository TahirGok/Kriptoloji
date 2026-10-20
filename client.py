import socket
import threading

HOST = '127.0.0.1'
PORT = 65432


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
