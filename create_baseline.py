from pathlib import Path
import json
import argparse
from Main.core import hash_file

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
            print("[WARN] Could not hash {rel}: {e}")
    return baseline

def main():
    parser = argparse.ArgumentParser(description="Create a file-integrity baseline (JSON).")
    parser.add_argument("folder", help="Folder to scan (root of your dataset).")
    parser.add_argument("-o", "--output", default="baseline.json",
                        help="Output JSON file (default: baseline.json).")
    parser.add_argument("-a", "--algo", default="sha256",
                        help="Hash algorithm (sha256, sha1, md5, etc.). Default: sha256")
    args = parser.parse_args()

    root = Path(args.folder).expanduser().resolve()
    if not root.is_dir():
        raise SystemExit(f"Folder not found: {root}")

    print(f"\nBuilding baseline for: {root}")
    print(f"Algorithm: {args.algo}")

    baseline = build_baseline(root, algo=args.algo)

    out_path = Path(args.output).resolve()
    out_path.write_text(json.dumps(baseline, indent=2, sort_keys=True))

    print(f"\nFiles hashed: {len(baseline)}")
    print(f"Baseline written to: {out_path}")

if __name__ == "__main__":
    main()