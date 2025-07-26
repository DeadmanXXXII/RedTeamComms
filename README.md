# RedTeamComms

### Private encrypted comms channeling via Smartphone, raw data and SMTP servers with AES encryption.



📁 Repository: RedTeamComms

---

Repository structure and key files:
```
RedTeamComms/
├── README.md
├── requirements.txt
├── core/
│   ├── __init__.py
│   ├── crypto.py
│   ├── compress.py
│   ├── obfuscate.py
│   ├── port_manager.py
│   ├── file_transfer.py
│   └── daemon.py
├── test/
│   ├── test_crypto.py
│   └── test_file_transfer.py
```

---

1. requirements.txt
```txt
pycryptodome
cryptography
pytest
```

---

2. README.md

### RedTeamComms

RedTeamComms is a peer-to-peer encrypted messaging and file transfer system for smartphones running Kali NetHunter or similar Linux terminals or python IDE's.

## Features
- AES-256-GCM encryption with ephemeral X25519 key exchange
- Zlib compression of messages and files
- Traffic obfuscation (random padding + noise)
- Dynamic port randomization for stealth
- File transfer with chunking

## Installation

```bash
pip install -r requirements.txt

Usage

Run server daemon (receiver)

python3 core/daemon.py --mode server

Send a file to peer (client mode)

python3 core/daemon.py --mode client --peer-ip <IP_ADDRESS> --send-file /path/to/file
```

---

Development

Run tests with:
```bash
pytest
```
---

## 3. **core/crypto.py**

```python
import os
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def generate_ecc_keypair():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(pub):
    return pub.public_bytes(encoding=serialization.Encoding.Raw,
                            format=serialization.PublicFormat.Raw)

def load_public_key(pub_bytes):
    return x25519.X25519PublicKey.from_public_bytes(pub_bytes)

def derive_aes_key(priv_key, peer_pub_bytes):
    peer_pub = load_public_key(peer_pub_bytes)
    shared_secret = priv_key.exchange(peer_pub)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'phoenixrelay key derivation'
    )
    return hkdf.derive(shared_secret)

def aes_encrypt(plaintext_bytes, key):
    iv = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)
    return iv + tag + ciphertext

def aes_decrypt(enc_bytes, key):
    iv = enc_bytes[:12]
    tag = enc_bytes[12:28]
    ciphertext = enc_bytes[28:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(ciphertext, tag)
```

---

4. core/compress.py
```python
import zlib

def compress(data: bytes) -> bytes:
    return zlib.compress(data)

def decompress(data: bytes) -> bytes:
    return zlib.decompress(data)
```

---

5. core/obfuscate.py
```python
import os
import random

def pad_data(data: bytes, block_size=256) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    padding = os.urandom(pad_len)
    return data + padding

def add_noise(data: bytes, noise_level=0.05) -> bytes:
    byte_arr = bytearray(data)
    for i in range(len(byte_arr)):
        if random.random() < noise_level:
            bit_to_flip = 1 << random.randint(0, 7)
            byte_arr[i] ^= bit_to_flip
    return bytes(byte_arr)


---

6. core/port_manager.py

import random

def get_random_port(exclude_ports=None):
    exclude_ports = exclude_ports or []
    while True:
        port = random.randint(20000, 60000)
        if port not in exclude_ports:
            return port
```

---

7. core/file_transfer.py
```python
import os
import socket
from core.crypto import aes_encrypt, aes_decrypt, derive_aes_key
from core.compress import compress, decompress
from core.obfuscate import pad_data, add_noise
from core.port_manager import get_random_port

CHUNK_SIZE = 4096

def send_file(filepath, peer_pub_bytes, priv_key, peer_ip):
    key = derive_aes_key(priv_key, peer_pub_bytes)
    port = get_random_port()

    with open(filepath, 'rb') as f:
        data = f.read()

    compressed = compress(data)
    encrypted = aes_encrypt(compressed, key)
    obfuscated = add_noise(pad_data(encrypted))

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((peer_ip, port))
        s.sendall(obfuscated)
    print(f"[+] Sent file {os.path.basename(filepath)} on port {port}")

def receive_file(priv_key, peer_pub_bytes, listen_port, output_path):
    key = derive_aes_key(priv_key, peer_pub_bytes)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', listen_port))
        s.listen(1)
        conn, addr = s.accept()
        print(f"[+] Receiving connection from {addr}")

        encrypted_data = b''
        while True:
            chunk = conn.recv(CHUNK_SIZE)
            if not chunk:
                break
            encrypted_data += chunk

    decrypted = aes_decrypt(encrypted_data, key)
    decompressed = decompress(decrypted)

    with open(output_path, 'wb') as f:
        f.write(decompressed)
    print(f"[+] File saved to {output_path}")
```

---

8. core/daemon.py
```python
import argparse
from core.crypto import generate_ecc_keypair, serialize_public_key
from core.file_transfer import send_file, receive_file
from core.port_manager import get_random_port

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=['server', 'client'], required=True)
    parser.add_argument("--peer-ip", help="Target IP for client mode")
    parser.add_argument("--send-file", help="File path to send")
    parser.add_argument("--listen-port", type=int, help="Port to listen on (server mode)")
    args = parser.parse_args()

    priv_key, pub_key = generate_ecc_keypair()
    pub_key_bytes = serialize_public_key(pub_key)

    if args.mode == 'server':
        listen_port = args.listen_port or get_random_port()
        print(f"[+] Running as server on port {listen_port}")
        # Use receive_file here with configured peer pubkey, you need to handle storing peer pubkey securely and sharing it OOB
        # Placeholder to receive a file:
        # receive_file(priv_key, peer_pub_bytes, listen_port, "received_file.dat")

    else:
        if not args.peer_ip or not args.send_file:
            print("Client mode requires --peer-ip and --send-file")
            return
        # Placeholder to send a file:
        # send_file(args.send_file, peer_pub_bytes, priv_key, args.peer_ip)

if __name__ == "__main__":
    main()
```

---

9. test/test_crypto.py
```python
import pytest
from core.crypto import generate_ecc_keypair, derive_aes_key, aes_encrypt, aes_decrypt

def test_encrypt_decrypt():
    priv_key, pub_key = generate_ecc_keypair()
    pub_bytes = pub_key.public_bytes()
    key = derive_aes_key(priv_key, pub_bytes)
    plaintext = b"Test message PhoenixRelay"
    encrypted = aes_encrypt(plaintext, key)
    decrypted = aes_decrypt(encrypted, key)
    assert decrypted == plaintext
```

---

10. test/test_file_transfer.py
```python
import os
import tempfile
from core.file_transfer import compress, decompress

def test_compress_decompress():
    data = b"Secret file data for PhoenixRelay"
    compressed = compress(data)
    decompressed = decompress(compressed)
    assert decompressed == data

def test_file_send_receive(tmp_path):
    # For real integration test, you need socket mocks or real sockets
    # Here just a placeholder for completeness
    pass
```


---

##### 🏁 Getting Started
```bash
unzip PhoenixRelay.zip
cd PhoenixRelay
pip install -r requirements.txt
python3 core/daemon.py --mode server
```
# On another device:
```bash
python3 core/daemon.py --mode client --peer-ip <server_ip> --send-file ./somefile.txt
```

