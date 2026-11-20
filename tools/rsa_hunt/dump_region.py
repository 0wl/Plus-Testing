#!/usr/bin/env python3
"""Decode Ghidra read_memory hex dump + write to fun_0017b438.bin."""
import sys, os, json
# This script expects a hexstring on stdin. For first-time setup we write
# the dump straight from clipboard. Later runs load from disk.
path = os.path.join(os.path.dirname(__file__), "fun_0017b438.bin")
hexstr = sys.stdin.read().strip()
data = bytes.fromhex(hexstr)
open(path, "wb").write(data)
print(f"wrote {len(data)} bytes to {path}")
