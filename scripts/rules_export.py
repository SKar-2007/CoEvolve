"""Export trained rules as a portable JSON package.

Usage:
    python scripts/rules_export.py --name my-rules --output rules.json
    python scripts/rules_export.py --name sql-rules --tags sql security
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from packages.evolution.portability import export_rules, save_package
from packages.evolution.store import PromptStore


def main():
    parser = argparse.ArgumentParser(description="Export trained rules as JSON package")
    parser.add_argument("--store-dir", default=".prompt_store", help="PromptStore directory")
    parser.add_argument("--name", required=True, help="Package name")
    parser.add_argument("--description", default="", help="Package description")
    parser.add_argument("--version", default="1.0.0", help="Package version")
    parser.add_argument("--author", default="", help="Author name")
    parser.add_argument("--tags", nargs="*", default=[], help="Tags for the package")
    parser.add_argument("--output", "-o", required=True, help="Output JSON file path")
    args = parser.parse_args()

    store = PromptStore(path=Path(args.store_dir))
    pkg = export_rules(
        store,
        name=args.name,
        description=args.description,
        version=args.version,
        author=args.author,
        tags=args.tags,
    )
    out = save_package(pkg, Path(args.output))
    print(f"Exported {len(pkg.rules)} rules to {out}")
    print(f"Package: {pkg.name} v{pkg.version} ({pkg.package_id[:8]})")


if __name__ == "__main__":
    main()
