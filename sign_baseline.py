from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

BASELINE = Path("baseline.json")
PRIV     = Path("ed25519_private.pem")
SIG      = Path("baseline.sig")

print(f"CWD: {Path.cwd()}")
print(f"Looking for:\n  - {BASELINE.resolve()}\n  - {PRIV.resolve()}")

if not BASELINE.exists():
    raise SystemExit(f"[ERROR] Missing {BASELINE}; run create_baseline.py first.")
if not PRIV.exists():
    raise SystemExit(f"[ERROR] Missing {PRIV}; run generate_keys.py first.")

baseline_bytes = BASELINE.read_bytes()
print(f"Baseline size: {len(baseline_bytes)} bytes")

try:
    private_key = serialization.load_pem_private_key(PRIV.read_bytes(), password=None)
    assert isinstance(private_key, ed25519.Ed25519PrivateKey)
except Exception as e:
    raise SystemExit(f"[ERROR] Failed to load private key: {e}")

signature = private_key.sign(baseline_bytes)
SIG.write_bytes(signature)
print(f"Wrote signature: {SIG.resolve()} ({SIG.stat().st_size} bytes)")

# quick verify to prove the .sig matches now
public_key = private_key.public_key()
public_key.verify(SIG.read_bytes(), baseline_bytes)
print("Signature verification: OK")