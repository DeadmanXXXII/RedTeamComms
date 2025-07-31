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
