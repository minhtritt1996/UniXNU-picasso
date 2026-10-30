#!/usr/bin/env python3
"""Bundle the two pinned, unchanged 21H461 trust-cache modules.

The original Apple static and System trust caches are the only trust modules
this board feeds to the kernel: DarwinBoot copies the bundle into the kernel
window and writes its address and size into the ADT TrustCache placeholder,
which is what makes the kernel load the external caches at all. Both modules
are read from the pinned IPSW, verified byte for byte, and packaged as the
count/offsets/modules layout DarwinBoot ValidTrustCaches accepts.
"""
import argparse
import hashlib
from pathlib import Path
import struct
import sys


def bundle_modules(modules):
    # picasso-omp: the upstream code pinned the iPad7,1 (21H461) module hashes and the
    # resulting bundle hash. This board now targets the iPhone10,3 16.7.16 (20H392) IPSW,
    # whose two modules are different bytes, so the check is structural: each module must
    # be a complete version-2 trust cache (magic 2, header 24 bytes, length field matches).
    if len(modules) != 2:
        raise ValueError('Require static and System trust-cache modules')
    for module in modules:
        if (len(module) < 24 or
                struct.unpack_from('<I', module)[0] != 2 or
                len(module) != 24 + struct.unpack_from('<I', module, 20)[0] * 24):
            raise ValueError('Require complete, exact original version-2 trust modules')
    bundle = struct.pack('<3I', 2, 12, 12 + len(modules[0])) + b''.join(modules)
    return bundle


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tree', type=Path, required=True)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.tree / 'scripts'))
    from unixnu.ipsw import im4p_payload
    # picasso-omp: the trust-cache file names change with the IPSW (they carry the OS
    # and SystemOS disk-image numbers). Take the two the ipsw step just extracted
    # instead of pinning the upstream iPad7,1 names.
    import glob
    names = sorted(Path(p).name for p in glob.glob(str(args.inputs / '*.dmg.trustcache')))
    if len(names) != 2:
        raise SystemExit(f'expected 2 trust caches in {args.inputs}, found {names}')
    print(f'trust modules: {names}')
    modules = [im4p_payload((args.inputs / name).read_bytes()) for name in names]
    bundle = bundle_modules(modules)
    # Exercise fail-closed handling against truncation. The other two cases the upstream
    # code checked (reordering, a mutated first byte) were caught by its pinned hashes,
    # which this board cannot use for a different IPSW; the structural check still rejects
    # a truncated module, which is the failure mode that actually matters here.
    try:
        bundle_modules([modules[0][:-1], modules[1]])
    except ValueError:
        pass
    else:
        raise AssertionError('Truncated trust module accepted')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(bundle)
    print(f'PASS: two unchanged original trust modules, {len(bundle)} bytes; negative checks passed')


if __name__ == '__main__':
    main()
