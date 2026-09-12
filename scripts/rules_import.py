"""Import rules from a portable JSON package.

Usage:
    python scripts/rules_import.py --input rules.json
    python scripts/rules_import.py --input rules.json --no-merge
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from packages.evolution.portability import import_rules, load_package
from packages.evolution.store import PromptStore


def main():
    parser = argparse.ArgumentParser(description="Import rules from JSON package")
    parser.add_argument("--store-dir", default=".prompt_store", help="PromptStore directory")
    parser.add_argument("--input", "-i", required=True, help="Input JSON package file")
    parser.add_argument("--no-merge", action="store_true", help="Replace all rules instead of merging")
    args = parser.parse_args()

    store = PromptStore(path=Path(args.store_dir))
    pkg = load_package(Path(args.input))

    print(f"Package: {pkg.name} v{pkg.version}")
    print(f"Rules in package: {len(pkg.rules)}")
    print(f"Current rules: {len(store.rules())}")

    count = import_rules(store, pkg, merge=not args.no_merge)
    print(f"Imported: {count} new rules")
    print(f"Total rules now: {len(store.rules())}")


if __name__ == "__main__":
    main()
