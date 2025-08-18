## File Integrity Monitor (FIM)

A lightweight Python-based File Integrity Monitor (FIM) that detects modifications, missing files, and unexpected changes using cryptographic hashes.  
Supports modern hash algorithms (SHA-2, SHA-3, BLAKE3) and optional Ed25519 signature verification to ensure baseline authenticity.  

---

## Features
- Generate and check baselines of file hashes
- Support for multiple algorithms:
  - `sha256` (default)
  - `sha3_256`
  - `sha512_256`
  - `blake3`
- Tamper-resistant baseline verification using Ed25519 signatures
- Configurable monitoring folder via environment variable or CLI
- Human-readable report of modified, missing, and unchanged files

---

## Installation
Clone the repository and install dependencies:
cryptography
blake3

---

## Usage
1. Create a baseline:
   
python create_baseline.py -a sha3_256

This generates:  
baseline.json (file hashes)  
baseline.sig (signature)  
ed25519_public.pem (public key)  

2. Verify files against baseline

python checker.py

4. Options

Override algorithm:

python checker.py -a blake3

Use custom baseline path:

python checker.py -b /path/to/baseline.json

Override monitored folder:

python checker.py -m /path/to/folder

Skip signature check (dev only):

python checker.py --skip-signature

---

## Example Output

=== File Integrity Report ===
Algorithm: sha256

Modified:
 - example.txt
    expected: 9c56cc51b374c3ba...
    current : 2f5a4c10c88293fd...

Missing:
 - notes/todo.txt

Unchanged:
 - data/config.yaml

Summary: 1 modified, 1 missing, 3 unchanged

---

## Security

Baseline JSON is signed with a private Ed25519 key

Verification uses the public key (ed25519_public.pem)

Prevents baseline tampering or unauthorized updates

---

## Roadmap

Add baseline auto-update option

Support recursive directory exclusions

JSON report export

CI integration
