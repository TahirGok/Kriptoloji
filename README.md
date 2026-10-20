# Güvenli Haberleşme Projesi

Bu proje, Karadeniz Teknik Üniversitesi Of Teknoloji Fakültesi Yazılım Mühendisliği Bölümü Kriptoloji dersi (Dr. Hakan AYDIN) kapsamında geliştirilecektir. Proje; sunucu ve istemciler arasında güvenli anahtar dağıtımı (RSA, Diffie-Hellman, ECC, Kyber) gerçekleştirerek AES-128 ile şifrelenmiş metin ve dosya aktarımı sağlayan bir haberleşme uygulaması olacaktır.

## 👥 Grup Üyeleri ve Görev Dağılımı

* **Tahir Buğrahan Gök (Lider):** Asimetrik Kriptografi algoritmalarının entegrasyonu (RSA, DH, ECC, Kyber), algoritmaların performans ölçümleri ve proje analizi.
* **Muhammed Safa Karaaslan:** Ağ ve Sunucu Altyapısı, soket programlama, istemciler arası veri yönlendirme ve sunucu mantığının kurulması.
* **Kadir Avcı:** Manuel AES algoritmasının kütüphanesiz olarak (S-box, round yapısı vb.) kodlanması, kütüphaneli sürümle karşılaştırması ve İstemci Arayüzünün (GUI/CLI) geliştirilmesi.

## 💻 Platform ve Teknolojiler

* **Programlama Dili:** Python
* **Platform:** Masaüstü Uygulaması
* **Kullanılan Temel Araçlar:**  Kriptografik Kütüphaneler, Wireshark (Paket Analizi için)

## 🔍 Wireshark İnceleme Notu
Haberleşme *65432* numaralı port üzerinden yapılmaktadır. 
guvensiz_mod.pcapng dosyasını Wireshark ile açtıktan sonra mesajları net görebilmek için filtre çubuğuna şunu yazabilirsiniz:
tcp.port == 65432
Ardından uzunluğu en yüksek olan [PSH, ACK] paketine sağ tıklayıp *Follow -> TCP Stream* diyerek açık metni görüntüleyebilirsiniz.






