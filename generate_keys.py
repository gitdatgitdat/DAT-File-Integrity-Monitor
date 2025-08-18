from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from pathlib import Path

PRIV = Path("ed25519_private.pem")
PUB  = Path("ed25519_public.pem")

# Create private key
private_key = ed25519.Ed25519PrivateKey.generate()

# Write private key (PEM, unencrypted)
PRIV.write_bytes(
    private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
)

# Write public key (PEM)
public_key = private_key.public_key()
PUB.write_bytes(
    public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
)

print(f"Wrote {PRIV} and {PUB}")