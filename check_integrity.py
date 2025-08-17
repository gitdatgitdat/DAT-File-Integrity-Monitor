import os
import sys
import json
import argparse
from pathlib import Path
from Main.core import hash_file

BASELINE_FILE = "baseline.json"
PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_MONITOR = PROJECT_ROOT / "Test"
ENV_MONITOR = os.getenv("FIM_FOLDER")
MONITOR_FOLDER = Path(ENV_MONITOR).expanduser().resolve() if ENV_MONITOR else DEFAULT_MONITOR

def load_baseline(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)

def resolve_path(p: str | Path) -> Path:
    p = Path(p)
    return p if p.is_absolute() else (MONITOR_FOLDER / p)

def main() -> None:
    parser = argparse.ArgumentParser(description="Check files against a baseline JSON.")
    parser.add_argument("-b", "--baseline", default=BASELINE_FILE,
                        help="Path to baseline JSON (default: baseline.json)")
    parser.add_argument("-m", "--monitor", default=None,
                        help="Override MONITOR_FOLDER (or set env FIM_FOLDER).")
    # Optional override if you ever need it (normally you won’t):
    parser.add_argument("-a", "--algo", default=None,
                        help="Override algorithm (normally read from baseline _meta.algo).")
    args = parser.parse_args()

    # Apply monitor override (CLI > env > default)
    global MONITOR_FOLDER
    MONITOR_FOLDER = Path(args.monitor).expanduser().resolve() if args.monitor else MONITOR_FOLDER

    baseline_path = Path(args.baseline).expanduser().resolve()
    try:
        raw = load_baseline(baseline_path)
    except FileNotFoundError:
        print(f"[ERROR] Baseline file not found: {baseline_path}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[ERROR] Baseline JSON is invalid: {e}")
        sys.exit(1)

    if isinstance(raw, dict) and "files" in raw and "_meta" in raw:
        files_map = raw["files"]
        baseline_algo = raw["_meta"].get("algo", "sha256")
    else:
        # Legacy flat dict baseline: { "rel/path.txt": "hash", ... }
        files_map = raw
        baseline_algo = "sha256"

    # Allow explicit override only if provided
    algo = (args.algo or baseline_algo).lower()

    modified = []
    missing = []
    unchanged = []

    for rel_path, expected_hash in files_map.items():
        target = resolve_path(rel_path)

        if not target.exists():
            missing.append(rel_path)
            continue

        try:
            current_hash = hash_file(str(target), algo=algo)
        except Exception as e:
            print(f"[ERROR] Could not hash {rel_path}: {e}")
            missing.append(rel_path)
            continue

        if current_hash.lower() == str(expected_hash).lower():
            unchanged.append(rel_path)
        else:
            modified.append((rel_path, expected_hash, current_hash))

    # Report Generation
    print("\n=== File Integrity Report ===")
    print(f"Algorithm: {algo}")

    if modified:
        print("\nModified:")
        for rel, exp_h, cur_h in modified:
            print(f" - {rel}")
            print(f"    expected: {exp_h}")
            print(f"    current : {cur_h}")

    if missing:
        print("\nMissing:")
        for rel in missing:
            print(f" - {rel}")

    if unchanged:
        print("\nUnchanged:")
        for rel in unchanged:
            print(f" - {rel}")

    # Summary line
    print(f"\nSummary: {len(modified)} modified, {len(missing)} missing, {len(unchanged)} unchanged")

    if not modified and not missing:
        print("\nAll files match the baseline")
        sys.exit(0)
    else:
        sys.exit(2)

if __name__ == "__main__":
    main()