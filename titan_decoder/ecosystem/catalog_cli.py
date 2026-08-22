"""List compatible entries from Titan's offline plugin catalog."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from titan_decoder.plugins.api import PLUGIN_API_VERSION
from titan_decoder.ecosystem.catalog import compatible_plugins, load_catalog


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="titan plugin-catalog")
    parser.add_argument("catalog", type=Path)
    parser.add_argument("--api-version", default=PLUGIN_API_VERSION)
    args = parser.parse_args(argv)
    plugins = compatible_plugins(load_catalog(args.catalog), args.api_version)
    print(json.dumps({"api_version": args.api_version, "plugins": plugins}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
