import os

from obelisk import encrypt, decrypt, hash, kdf, wrap, unwrap, KEY_BYTES, NONCE_BYTES


def line(t):
    print("\n" + t)
    print("-" * len(t))


def main():
    line("OBELISK  -  one permutation, four classified-grade functions")

    line("[BATON / WAGE]  authenticated encryption")
    key = os.urandom(KEY_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    msg = b"Top secret: the eagle lands at midnight."
    ad = b"channel=alpha;seq=7"
    ct, tag = encrypt(key, nonce, msg, ad)
    print(f"  plaintext : {msg.decode()}")
    print(f"  ciphertext: {ct.hex()}")
    print(f"  tag       : {tag.hex()}")
    print(f"  decrypted : {decrypt(key, nonce, ct, tag, ad).decode()}")

    line("[JOSEKI]  protecting a key at rest (key-wrap)")
    kek = os.urandom(32)
    device_key = os.urandom(KEY_BYTES)
    blob = wrap(kek, device_key, context=b"device-42")
    print(f"  device key : {device_key.hex()}")
    print(f"  wrapped    : {blob.hex()}")
    print(f"  unwrapped  : {unwrap(kek, blob, context=b'device-42').hex()}")

    line("[hash / KDF]  fingerprint + key derivation")
    print(f"  hash('firmware.bin') = {hash(b'firmware.bin').hex()}")
    print(f"  kdf(master, 32)      = {kdf(b'master-secret', 32).hex()}")

    line("[FIREFLY]  hybrid key agreement (optional, needs 'cryptography')")
    try:
        from obelisk.kex import generate_keypair, establish_channel_keys
        a_priv, a_pub = generate_keypair()
        b_priv, b_pub = generate_keypair()
        a_send, a_recv = establish_channel_keys(a_priv, b_pub, a_pub)
        b_send, b_recv = establish_channel_keys(b_priv, a_pub, b_pub)
        agree = (a_send == b_recv) and (a_recv == b_send)
        print(f"  Alice/Bob derived matching channel keys: {agree}")
        print(f"  channel key (A->B): {a_send.hex()}")
    except RuntimeError as e:
        print(f"  skipped: {e}")

    print("\ndone.")


if __name__ == "__main__":
    main()
