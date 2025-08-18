from pathlib import Path
from datetime import datetime, timezone
import os
import json
import argparse
from Main.core import hash_file

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

with open("ed25519_public.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

baseline_bytes = Path(args.baseline).read_bytes()
sig = Path("baseline.sig").read_bytes()

try:
    public_key.verify(sig, baseline_bytes)
except Exception:
    raise SystemExit("[ERROR] Baseline signature invalid!")

# Allowed algorithms
SAFE_ALGOS = ["sha256", "sha3_256", "sha512_256", "blake3"]

# File pathing
PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_MONITOR = PROJECT_ROOT / "Test"
ENV_MONITOR = os.getenv("FIM_FOLDER")
MONITOR_FOLDER = Path(ENV_MONITOR).expanduser().resolve() if ENV_MONITOR else DEFAULT_MONITOR

def resolve_path(p: str | Path) -> Path:
    p = Path(p)
    return p if p.is_absolute() else (MONITOR_FOLDER / p)

# Directory to monitor and baseline creation
def iter_files(root: Path, exclude_hidden: bool = True):
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if exclude_hidden and any(part.startswith(".") for part in p.relative_to(root).parts):
            continue
        yield p

def build_baseline(root: Path, algo: str = "sha256", chunk_size: int = 65536) -> dict:
    baseline = {}
    for path in iter_files(root):
        rel = path.relative_to(root).as_posix()
        try:
            digest = hash_file(str(path), algo=algo, chunk_size=chunk_size)
            baseline[rel] = digest
        except Exception as e:
            print(f"[WARN] Could not hash {rel}: {e}")
    return baseline

def pick_algo_interactively(default="sha256") -> str:
    print("\nSelect hash algorithm:")
    for i, name in enumerate(SAFE_ALGOS, 1):
        tag = " (default)" if name == default else ""
        print(f"  {i}) {name}{tag}")
    choice = input("Enter number (or press Enter for default): ").strip()
    if not choice:
        return default
    try:
        idx = int(choice)
        if 1 <= idx <= len(SAFE_ALGOS):
            return SAFE_ALGOS[idx - 1]
    except ValueError:
        pass
    print("Invalid choice, using default.")
    return default

def main():
    parser = argparse.ArgumentParser(description="Create a file-integrity baseline (JSON).")
    parser.add_argument("folder", nargs="?", default=None,
                        help="Folder to scan (defaults to MONITOR_FOLDER).")
    parser.add_argument("-m", "--monitor", default=None,
                        help="Override MONITOR_FOLDER (or set env FIM_FOLDER).")
    parser.add_argument("-o", "--output", default="baseline.json",
                        help="Output JSON file (default: baseline.json).")
    parser.add_argument("-a", "--algo", default=None,
        help="Hash algorithm. If omitted, you’ll be prompted. "
            "Options: sha256, sha3_256, sha512_256, blake3 (default: sha256)")
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Don’t prompt; if --algo is omitted, default to sha256."
    )
    args = parser.parse_args()

    # Monitor root resolution
    monitor_root = Path(args.monitor).expanduser().resolve() if args.monitor else MONITOR_FOLDER
    root = resolve_path(args.folder) if args.folder else monitor_root
    if not root.is_dir():
        raise SystemExit(f"Folder not found: {root}")

    # Decide algorithm
    if args.algo:
        algo = args.algo.lower()
        if algo not in SAFE_ALGOS:
            raise SystemExit(f"Unsupported algorithm '{algo}'. Choose from: {', '.join(SAFE_ALGOS)}")
    else:
        algo = "sha256" if args.non_interactive else pick_algo_interactively(default="sha256")

    print(f"\nBuilding baseline for: {root}")
    print(f"Algorithm: {algo}")

    files_map = build_baseline(root, algo=algo)

    # Embed metadata so the checker knows which algo to use
    doc = {
        "_meta": {
            "version": 1,
            "algo": algo,
            "created": datetime.now(timezone.utc).isoformat(),
            "root": str(root)
        },
        "files": files_map
    }

    out_path = Path(args.output).resolve()
    out_path.write_text(json.dumps(doc, indent=2, sort_keys=True))

    print(f"\nFiles hashed: {len(files_map)}")
    print(f"Baseline written to: {out_path}")

if __name__ == "__main__":
    main()