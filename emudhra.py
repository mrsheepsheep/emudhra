#!/usr/bin/env python3
"""Compatibility shim: runs the emudhra package from a source checkout.

Prefer the installed entry point:  emudhra <command> ...
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from emudhra import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
