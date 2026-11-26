"""Encrypt a video so the site can only play it with a code.

    python tools/encrypt_video.py SOURCE.mp4 media/OUT.enc   (asks for the code, never stores it)

Format read by index.html: b"DRV1" | salt (16) | iv (12) | AES-256-GCM ciphertext+tag.
Key = PBKDF2-HMAC-SHA256(code, salt, 600000 iterations). A wrong code fails the GCM tag check.
To change the code: re-run this on the original video and push the new .enc file.
"""
import getpass, os, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ITER = 600_000


def main(src, out):
    code = os.environ.get("VIDEO_CODE") or getpass.getpass("Code: ")
    salt, iv = os.urandom(16), os.urandom(12)
    key = PBKDF2HMAC(hashes.SHA256(), 32, salt, ITER).derive(code.encode())
    data = open(src, "rb").read()
    with open(out, "wb") as f:
        f.write(b"DRV1" + salt + iv + AESGCM(key).encrypt(iv, data, None))
    print("encrypted", src, "->", out, len(data) // 1_000_000, "MB")


if __name__ == "__main__":
    main(*sys.argv[1:3])
