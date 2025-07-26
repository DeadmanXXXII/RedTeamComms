# RedTeamComms

I built this project because of this course im sitting.
Operational communication is the core aspect of having finesse and precision during "go time".

[OpSec and Anonymity course](https://redteamleaders.coursestack.com/courses/e07e722b-642c-4191-b3a3-29cf39236968/take/11-the-origins-of-opsec-from-military-doctrine-to-offensive-cyber-operations)


### RedTeamComms.

A covert communication system for red teams, designed for encrypted, obfuscated, and compressed messaging over cellular data networks. It utilizes AES encryption with ephemeral keys, ECC-based key exchange, randomized port communication, and supports file and message transfers between smartphones running Kali NetHunter.


---

### Features

AES-256 Encryption (single-use keys)

ECC Key Exchange (ECIES over Curve25519)

Compressed + Obfuscated Traffic

Randomized Port Selection

File and Message Transfer Support

Listener Server for Receiving Encrypted Payloads

Optimized for Android NetHunter Devices



---

##### Project Structure
```
RedTeamComms/
├── README.md
├── requirements.txt
├── config.json
├── sender.py              # Client to encrypt, compress, and transmit messages/files
├── receiver.py            # Listener for receiving, decrypting, decompressing payloads
├── crypto/
│   ├── __init__.py
│   ├── aes.py             # AES encryption/decryption utilities
│   └── ecies.py           # ECC key generation and ECIES exchange
├── utils/
│   ├── __init__.py
│   ├── obfuscation.py     # XOR/rotational/stream obfuscators
│   └── compression.py     # Gzip compression utilities
└── ports/
    └── port_randomizer.py # Handles ephemeral port selection and validation
```

---

requirements.txt
```txt
cryptography
pycryptodome
```

---

crypto/aes.py
```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

BLOCK_SIZE = 16

def pad(data):
    padding = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([padding] * padding)

def unpad(data):
    return data[:-data[-1]]

def generate_aes_key():
    return get_random_bytes(32)

def encrypt_aes(key, plaintext):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext))
    return base64.b64encode(iv + ciphertext)

def decrypt_aes(key, ciphertext):
    raw = base64.b64decode(ciphertext)
    iv = raw[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(raw[16:]))
```

---

crypto/ecies.py
```python
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def generate_keypair():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def derive_shared_key(private_key, peer_public_bytes):
    peer_public = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
    shared = private_key.exchange(peer_public)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'RedTeamComms'
    ).derive(shared)
```

---

utils/obfuscation.py
```python
def xor(data, key=0xAA):
    return bytes(b ^ key for b in data)
```

---

utils/compression.py
```python
import gzip
import io

def compress(data: bytes) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode='wb') as f:
        f.write(data)
    return buf.getvalue()

def decompress(data: bytes) -> bytes:
    with gzip.GzipFile(fileobj=io.BytesIO(data), mode='rb') as f:
        return f.read()
```

---

ports/port_randomizer.py
```python
import random
import socket

def get_random_open_port():
    for _ in range(100):
        port = random.randint(1024, 65535)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("0.0.0.0", port))
                return port
            except OSError:
                continue
    raise Exception("No free port found")
```

---

sender.py
```python
from crypto.aes import generate_aes_key, encrypt_aes
from crypto.ecies import generate_keypair, derive_shared_key
from utils.compression import compress
from utils.obfuscation import xor
import socket
import json

receiver_pub_key = ...  # Load from config or peer
private_key, public_key = generate_keypair()
shared_key = derive_shared_key(private_key, receiver_pub_key)

# Sample plaintext
plaintext = b"Secret Message"
compressed = compress(plaintext)
obfuscated = xor(compressed)
encrypted = encrypt_aes(shared_key, obfuscated)

port = 5005  # or use port_randomizer
s = socket.socket()
s.connect(("receiver-ip", port))
s.send(public_key.public_bytes())
s.send(encrypted)
s.close()
```

---

receiver.py
```python
from crypto.aes import decrypt_aes
from crypto.ecies import generate_keypair, derive_shared_key
from utils.compression import decompress
from utils.obfuscation import xor
import socket

private_key, public_key = generate_keypair()

s = socket.socket()
s.bind(("0.0.0.0", 5005))
s.listen(1)
conn, _ = s.accept()

peer_pub = conn.recv(32)
shared_key = derive_shared_key(private_key, peer_pub)

encrypted = conn.recv(4096)
obfuscated = decrypt_aes(shared_key, encrypted)
compressed = xor(obfuscated)
plaintext = decompress(compressed)
print("Received:", plaintext)
```

##### Stay silent, stay shady.
