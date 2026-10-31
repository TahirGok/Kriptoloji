"""Sunucu ve istemcinin ortak kullandığı mesaj çerçeveleme (framing) yardımcıları.

TCP bir bayt akışıdır: iki send() tek recv()'de birleşebilir, tek bir send() de
birkaç recv()'e bölünebilir. Bu yüzden el sıkışma bittikten sonra her mesaj şu
çerçeveyle gönderilir:

    +----------------+---------+----------------------+
    | uzunluk (4 B)  | tür (1 B)| veri (uzunluk kadar) |
    +----------------+---------+----------------------+

uzunluk: "veri" kısmının bayt sayısı (tür baytı dahil değil), big-endian.
"""
import struct

# Mesaj türleri. Dosya aktarımı eklenince yeni türler buraya girecek.
TIP_METIN = b'T'

BASLIK = struct.Struct('>I')       # 4 baytlık işaretsiz tamsayı
MAX_VERI = 16 * 1024 * 1024        # Bozuk/kötü niyetli uzunluklara karşı sınır (16 MB)


def _tam_oku(sock, n):
    """Soketten tam olarak n bayt okur. Bağlantı baştan kapanmışsa None döner."""
    parcalar = []
    kalan = n
    while kalan > 0:
        parca = sock.recv(kalan)
        if not parca:
            if kalan == n:
                return None                      # hiç veri gelmeden kapandı
            raise ConnectionError("Bağlantı mesajın ortasında koptu.")
        parcalar.append(parca)
        kalan -= len(parca)
    return b''.join(parcalar)


def mesaj_gonder(sock, tip, veri):
    """(tür, veri) çiftini çerçeveleyip gönderir."""
    if len(tip) != 1:
        raise ValueError("Tür tek bayt olmalıdır.")
    if len(veri) > MAX_VERI:
        raise ValueError("Mesaj çok büyük.")
    sock.sendall(BASLIK.pack(len(veri)) + tip + veri)


def mesaj_al(sock):
    """Bir çerçeve okur ve (tür, veri) döner. Bağlantı temiz kapandıysa None döner."""
    baslik = _tam_oku(sock, BASLIK.size)
    if baslik is None:
        return None
    (uzunluk,) = BASLIK.unpack(baslik)
    if uzunluk > MAX_VERI:
        raise ValueError(f"Geçersiz mesaj uzunluğu: {uzunluk}")
    tip = _tam_oku(sock, 1)
    if tip is None:
        raise ConnectionError("Bağlantı mesajın ortasında koptu.")
    if uzunluk == 0:
        return tip, b''
    veri = _tam_oku(sock, uzunluk)
    if veri is None:
        raise ConnectionError("Bağlantı mesajın ortasında koptu.")
    return tip, veri