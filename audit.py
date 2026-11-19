#!/usr/bin/env python3
"""Entry point: python3 audit.py audit <export.json> --out out/"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from automation_audit.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
