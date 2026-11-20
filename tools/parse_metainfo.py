#!/usr/bin/env python3
# Parse MST2 metainfo2.txt into a structured JSON graph.
import re, json, sys, os

SEP = '\\'

def parse(path):
    txt = open(path, encoding='latin1').read()
    sections = {}
    current = None
    for raw in txt.splitlines():
        line = raw.rstrip()
        m = re.match(r'^\[([^\]]+)\]$', line)
        if m:
            current = m.group(1)
            sections[current] = {}
            continue
        if not line or line.startswith('#'):
            continue
        if current is None:
            continue
        m = re.match(r'^(\w+)\s*=\s*"?(.*?)"?\s*$', line)
        if m:
            k, v = m.group(1), m.group(2)
            sections[current][k] = v
    return sections

def build_graph(sections):
    graph = {
        'common': sections.get('common', {}),
        'devices': {},
    }
    for sec, kv in sections.items():
        if sec in ('common', 'Signature'):
            continue
        parts = sec.split(SEP)
        if len(parts) == 1:
            graph['devices'].setdefault(parts[0], {'_meta': kv, 'modules': {}})
        elif len(parts) >= 4:
            dev, mod, ver, chan = parts[0], parts[1], parts[2], parts[3]
            typ = parts[4] if len(parts) >= 5 else chan
            d = graph['devices'].setdefault(dev, {'_meta': {}, 'modules': {}})
            m = d['modules'].setdefault(mod, {'versions': {}})
            v = m['versions'].setdefault(ver, {'channels': {}})
            c = v['channels'].setdefault(chan, {'types': {}})
            c['types'][typ] = kv
    return graph

def main():
    src = sys.argv[1] if len(sys.argv) > 1 else '../MST2_EU_VW_ZR_P0254T/metainfo2.txt'
    sections = parse(src)
    graph = build_graph(sections)
    outdir = os.path.dirname(os.path.abspath(__file__))
    full = os.path.join(outdir, '..', 'analysis', 'metainfo_full.json')
    summ = os.path.join(outdir, '..', 'analysis', 'metainfo_summary.json')
    json.dump(graph, open(full, 'w', encoding='utf-8'), indent=2)
    summary = {
        'common': graph['common'],
        'device_count': len(graph['devices']),
        'devices': {d: {
            'module_count': len(info['modules']),
            'modules': sorted(info['modules'].keys()),
        } for d, info in graph['devices'].items()},
        'signature': sections.get('Signature', {}),
    }
    json.dump(summary, open(summ, 'w', encoding='utf-8'), indent=2)
    print(f'devices: {len(graph["devices"])}')
    for d, info in graph['devices'].items():
        print(f'  {d}: {len(info["modules"])} modules')
    print(f'signature parts: {len(sections.get("Signature", {}))}')

if __name__ == '__main__':
    main()
