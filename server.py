import socket

HOST = '127.0.0.1' 
PORT = 65432       

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print(f"Sunucu {HOST}:{PORT} adresinde dinleniyor...")

    conn, addr = s.accept()
    with conn:
        print(f"Bağlantı sağlandı: {addr}")
        while True:
            data = conn.recv(1024)
            if not data:
                break
            print(f"İstemciden gelen mesaj: {data.decode('utf-8')}")