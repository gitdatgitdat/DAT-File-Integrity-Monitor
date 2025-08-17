from __future__ import annotations
import hashlib
from typing import Iterable

try:
    import blake3 as _blake3  # pip install blake3
except ImportError:
    _blake3 = None

# Accept common aliases; keep only the ones you want to expose
SAFE_ALGOS = {
    "sha256": "sha256",
    "sha3_256": "sha3_256",        # Python hashlib
    "sha512_256": "sha512_256",    # Python hashlib
    "blake3": "blake3",            # external package
}

def _new_hasher(name: str):
    name = name.lower()
    if name not in SAFE_ALGOS:
        raise ValueError(f"Unsupported algorithm '{name}'. Supported: {', '.join(SAFE_ALGOS)}")

    algo = SAFE_ALGOS[name]
    if algo == "blake3":
        if _blake3 is None:
            raise RuntimeError("blake3 is not installed. Run: pip install blake3")
        return _blake3.blake3()  # returns a hasher with .update()/.hexdigest()
    else:
        # hashlib covers sha256, sha3_256, sha512_256, etc.
        return hashlib.new(algo)

def hash_file(path: str, algo: str = "sha256", chunk_size: int = 65536) -> str:
    h = _new_hasher(algo)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()