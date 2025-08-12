import hashlib

def hash_file(path: str, algo: str = "sha256", chunk_size: int = 65536) -> str:
    """
    Return the hex digest of a file using the given hashing algorithm.
    Reads the file in chunks to handle large files safely.
    """
    # Validate algorithm name
    h = hashlib.new(algo)

    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)

    return h.hexdigest()
