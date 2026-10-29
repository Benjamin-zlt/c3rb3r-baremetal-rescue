#!/usr/bin/env python3
"""Read the 48-byte session master (IV16 + AES key32) out of a process dump.

    python3 extract_master.py <dumpdir> <out.bin> [profile.json]

dumpdir must hold mem.bin + mem.idx from dump_process_memory.py. Only valid for
the sample described by the profile (non-PIE, fixed global addresses); check
exe.bin's sha256 against the profile first. The result is a candidate until
verify_pairs.py decrypts known files byte-for-byte.
"""
import hashlib, json, os, struct, sys

HERE = os.path.dirname(os.path.abspath(__file__))


def load_idx(path):
    regions = []
    for line in open(path):
        off, rng = line.split()[:2]
        s, e = (int(x, 16) for x in rng.split('-'))
        regions.append((s, e, int(off)))
    return regions


def read_va(mem, regions, va, n):
    for s, e, off in regions:
        if s <= va and va + n <= e:
            mem.seek(off + va - s); return mem.read(n)
    raise ValueError('address %#x not in a dumped rw region' % va)


def main(dump, out, profile_path):
    prof = json.load(open(profile_path))
    exe = os.path.join(dump, 'exe.bin')
    if os.path.exists(exe):
        h = hashlib.sha256(open(exe, 'rb').read()).hexdigest()
        if h != prof['packed_sha256']:
            sys.exit('exe.bin %s does not match the profile sample; addresses would be wrong' % h)
    regions = load_idx(os.path.join(dump, 'mem.idx'))
    with open(os.path.join(dump, 'mem.bin'), 'rb') as mem:
        mode = read_va(mem, regions, prof['mode_va'], 1)[0]
        if mode != 0x20:
            sys.exit('runtime crypto mode %#x, expected 0x20 (0x21 writes decoy keys)' % mode)
        ptr = struct.unpack('<Q', read_va(mem, regions, prof['master_pointer_va'], 8))[0]
        if not ptr:
            sys.exit('master pointer is NULL')
        master = read_va(mem, regions, ptr, 48)
    if not any(master[:16]) or not any(master[16:]):
        sys.exit('master material is empty')
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    with os.fdopen(fd, 'wb') as f:
        f.write(master)
    print('mode 0x20, master pointer %#x, 48 bytes written to %s' % (ptr, out))


if __name__ == '__main__':
    if len(sys.argv) not in (3, 4):
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2],
         sys.argv[3] if len(sys.argv) == 4 else os.path.join(HERE, '..', 'profiles', 'libgld-802ac85d.json'))
