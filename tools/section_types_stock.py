#!/usr/bin/env python3
import os
SEP='\\'
m=open(os.path.join(os.path.dirname(__file__),'..','MST2_EU_VW_ZR_P0254T','metainfo2.txt'),encoding='latin1').read()
lines=m.splitlines()
secs={}
for L in lines:
    if L.startswith('[') and L.endswith(']'):
        hdr=L[1:-1]
        parts=hdr.split(SEP)
        if len(parts)>=5:
            typ=parts[-1]
            secs.setdefault(typ,[]).append(hdr)
for t,l in secs.items():
    print(f'{t}: {len(l)} sections')
    print(f'  first: {l[0]}')
# Print a Dir or File example block
for t in ('Dir','File','bootloader','Application'):
    if t in secs:
        hdr=secs[t][0]
        tgt='['+hdr+']'
        print(f'\n--- example {t} block: {hdr} ---')
        for i,line in enumerate(lines):
            if line==tgt:
                print(line)
                for j in range(i+1, min(i+20,len(lines))):
                    if lines[j].startswith('['): break
                    print(lines[j])
                break
