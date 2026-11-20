#!/usr/bin/env python3
"""Probe whether the toolbox signed metainfo actually binds the payload hashes."""
import hashlib, os, re, sys
TB = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'extracted', 'toolbox')
meta = open(os.path.join(TB, 'metainfo2.txt'), encoding='latin1').read()

def find_sections(prefix):
    # prefix e.g. 'cpu\\InfoFile\\1\\default\\File'
    out = []
    lines = meta.splitlines()
    i = 0
    while i < len(lines):
        L = lines[i].rstrip()
        if L.startswith('[') and L.endswith(']') and prefix in L[1:-1]:
            header = L
            body = []
            i += 1
            while i < len(lines) and not lines[i].startswith('['):
                body.append(lines[i])
                i += 1
            out.append((header, '\n'.join(body)))
        else:
            i += 1
    return out

for hdr_substr in ('InfoFile\\1\\default\\File', 'onlineservices\\1\\default\\Dir', 'onlineservices\\1\\default\\Application'):
    secs = find_sections(hdr_substr)
    print(f'--- "{hdr_substr}" => {len(secs)} section(s) ---')
    for h, b in secs[:3]:
        print(h)
        print(b)
        print()

# Dump hashes.txt
hashes_path = os.path.join(TB, 'cpu', 'onlineservices', '1', 'default', 'hashes.txt')
print('--- hashes.txt ---')
print(open(hashes_path).read()[:2000])

# Compare: for a few toolbox ESD files, compute SHA1 and see if hashes.txt matches
esd_dir = os.path.join(TB, 'cpu', 'onlineservices', '1', 'default', 'tsd', 'etc', 'persistence', 'esd')
if os.path.isdir(esd_dir):
    for fn in sorted(os.listdir(esd_dir))[:5]:
        fp = os.path.join(esd_dir, fn)
        if os.path.isfile(fp):
            data = open(fp, 'rb').read()
            print(f'{fn}: size={len(data)} sha1={hashlib.sha1(data).hexdigest()}')
