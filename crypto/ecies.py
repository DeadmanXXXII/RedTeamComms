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
