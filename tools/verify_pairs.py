#!/usr/bin/env python3
"""Validate a master candidate against known plaintext.

    python3 verify_pairs.py <master.bin> <pairs.tsv>

pairs.tsv: one "<encrypted .L0CK3D path>\t<intact original path>" per line,
e.g. files that also exist as an unencrypted duplicate elsewhere. Writes
nothing next to the inputs; decrypts into a temp dir and compares SHA-256.
Pick pairs that cover all three modes (0x24 full, 0x25 partial, 0x26 first MiB).
A mismatch on a tiny metadata file (Thumbs.db, .DS_Store) usually means the
"original" is a different file of the same size, not a wrong key.
"""
import collections, hashlib, os, sys, tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import c3dec


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()


def main(master_path, tsv):
    master = open(master_path, 'rb').read()
    stats = collections.Counter()
    with tempfile.TemporaryDirectory() as tmp:
        for n, line in enumerate(open(tsv, encoding='utf-8')):
            enc, orig = line.rstrip('\n').split('\t')[:2]
            out = os.path.join(tmp, str(n))
            try:
                h, mode, pct = c3dec.decrypt_file(enc, out, master)
                res = 'OK' if h == sha(orig) else 'MISMATCH'
            except Exception as ex:
                res, mode, pct = 'FAIL', 0, 0
                print('FAIL', enc, ex)
            stats[(res, hex(mode))] += 1
            if res == 'MISMATCH':
                print('MISMATCH', enc)
            if os.path.exists(out):
                os.remove(out)
    for k, v in sorted(stats.items()):
        print(v, *k)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
