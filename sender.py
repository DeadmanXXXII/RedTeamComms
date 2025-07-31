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
