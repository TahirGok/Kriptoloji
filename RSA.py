import time
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_rsa_and_measure_time():
    # zaman baslatici
    start_time = time.time()

    # anahtar cifti uretimi
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    #zamanlayiciyi durdur
    end_time = time.time()

    # Saniyeyi milisaniyeye çevir
    elapsed_time_ms = (end_time - start_time) * 1000

    print(f"RSA-2048 Anahtar Üretim Süresi: {elapsed_time_ms:.2f} ms")
    return private_key, public_key

if __name__ == "__main__":
    generate_rsa_and_measure_time()