import os
import sys
import json

from Main.core import hash_file

BASELINE_FILE = "baseline.json"
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

def load_baseline(path: str = BASELINE_FILE) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
    
def resolve_path(p: str) -> str:
    """Resolve a path from the baseline to an absolute path on disk."""
    return p if os.path.isabs(p) else os.path.join(PROJECT_ROOT, p)

def main() -> None:
    try:
        baseline = load_baseline()
    except FileNotFoundError:
        print(f"[ERROR] Baseline file not found: {BASELINE_FILE}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[ERROR] Baseline JSON is invalid: {e}")
        sys.exit(1)

    modified = []
    missing = []
    unchanged = []

    for rel_path, expected_hash in baseline.items():
        target = resolve_path(rel_path)

        if not os.path.exists(target):
            missing.append(rel_path)
            continue

        try:
            current_hash = hash_file(target)  # sha256 by default
        except Exception as e:
            print(f"[ERROR] Could not hash {rel_path}: {e}")
            missing.append(rel_path)
            continue

        if current_hash.lower() == expected_hash.lower():
            unchanged.append(rel_path)
        else:
            modified.append((rel_path, expected_hash, current_hash))

    # Report Generation
    print("\n=== File Integrity Report ===")

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

    if not modified and not missing:
        print("\nAll files match the baseline")
        sys.exit(0)
    else:
        sys.exit(2)


if __name__ == "__main__":
    main()