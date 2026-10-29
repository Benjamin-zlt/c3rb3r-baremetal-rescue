"""C3RB3R / .L0CK3D file format for the libgld sample 802ac85d (Linux x86_64).

ChaCha8 (32-byte key, 8-byte nonce, 64-bit block counter) over 1-5 byte ranges,
per-file key wrapped with AES-256-CBC under a per-run session master
(IV16 + key32) that only lives in the encryptor's memory.

Format credit: https://github.com/soimy/c3rb3r-rescue
"""
import hashlib
import struct

import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

FOOT = 588                 # footer appended to every encrypted file
CALL = 5 * 1024 * 1024     # the sample processes at most 5 MiB per cipher call
FIRST = 1024 * 1024        # mode 0x26: first 1 MiB only
# mode 0x25 partial parameter -> percent of the file per encrypted segment
PF = {10: 4, 15: 5, 20: 7, 25: 9, 30: 10, 35: 12, 40: 14, 50: 10, 60: 20, 70: 23, 80: 27}


def chacha(data, key, nonce, ctr, rounds=8):
    """One process_bytes call. A short final block still consumes a full counter step."""
    n = (len(data) + 63) // 64
    if not n:
        return b'', ctr
    init = np.empty((16, n), np.uint32)
    init[:12] = np.array(struct.unpack('<12I', b'expand 32-byte k' + key), np.uint32)[:, None]
    c = np.arange(n, dtype=np.uint64) + np.uint64(ctr)
    init[12] = c.astype(np.uint32); init[13] = (c >> np.uint64(32)).astype(np.uint32)
    init[14:] = np.array(struct.unpack('<2I', nonce), np.uint32)[:, None]
    x = init.copy()

    def rot(v, r):
        return (v << np.uint32(r)) | (v >> np.uint32(32 - r))

    def q(a, b, c_, d):
        x[a] += x[b]; x[d] = rot(x[d] ^ x[a], 16)
        x[c_] += x[d]; x[b] = rot(x[b] ^ x[c_], 12)
        x[a] += x[b]; x[d] = rot(x[d] ^ x[a], 8)
        x[c_] += x[d]; x[b] = rot(x[b] ^ x[c_], 7)

    for _ in range(rounds // 2):
        q(0, 4, 8, 12); q(1, 5, 9, 13); q(2, 6, 10, 14); q(3, 7, 11, 15)
        q(0, 5, 10, 15); q(1, 6, 11, 12); q(2, 7, 8, 13); q(3, 4, 9, 14)
    x += init
    ks = np.frombuffer(x.T.astype('<u4').tobytes(), np.uint8, count=len(data))
    return np.bitwise_xor(np.frombuffer(data, np.uint8), ks).tobytes(), ctr + n


def chacha8(data, key, nonce, ctr):
    return chacha(data, key, nonce, ctr, 8)


def segments(size, mode, pct):
    """Encrypted byte ranges for a file of the original size."""
    if mode == 0x24:
        return [(0, size)]
    if mode == 0x26:
        return [(0, min(size, FIRST))]
    if mode != 0x25 or pct not in PF:
        raise ValueError('unsupported mode %x/%d' % (mode, pct))
    ln = (size // 100) * PF[pct]; cnt = 5 if pct == 50 else 3
    gap = ln if pct == 50 else (size - 3 * ln) // 2
    return [(i * (ln + gap), ln) for i in range(cnt)]


def parse(footer, master):
    """Unwrap the per-file key. Footer layout (offsets inside the 588 bytes):
    0..48 AES-CBC(file_key32 + nonce8 + nonce8), 568 session marker,
    572 file mode, 573 partial parameter, 574 crypto mode, 580 uint64 original size."""
    mode, pct, cm, res = footer[572:576]
    size = struct.unpack_from('<Q', footer, 580)[0]
    if cm != 0x20:
        raise ValueError('crypto mode %x (0x21 = decoy material, not decryptable)' % cm)
    d = Cipher(algorithms.AES(master[16:]), modes.CBC(master[:16])).decryptor()
    rec = d.update(footer[:48]) + d.finalize()
    if rec[32:40] != rec[40:48]:
        raise ValueError('nonce check failed (wrong master or different session)')
    return rec[:32], rec[32:40], mode, pct, size


def decrypt_file(src, dst, master):
    """Write the plaintext of encrypted file src to the new file dst. Returns (sha256, mode, pct)."""
    with open(src, 'rb') as f:
        f.seek(-FOOT, 2); footer = f.read(FOOT); total = f.tell()
        key, nonce, mode, pct, size = parse(footer, master)
        if size != total - FOOT:
            raise ValueError('size mismatch / appended data')
        f.seek(0); h = hashlib.sha256(); ctr = 0; pos = 0
        with open(dst, 'xb') as o:
            def xfer(n, enc):
                nonlocal ctr, pos
                while n:
                    a = min(n, CALL); b = f.read(a)
                    if len(b) != a:
                        raise ValueError('short read')
                    if enc:
                        b, ctr = chacha8(b, key, nonce, ctr)
                    o.write(b); h.update(b); n -= a; pos += a
            for off, ln in segments(size, mode, pct):
                xfer(off - pos, False); xfer(ln, True)
            xfer(size - pos, False)
    return h.hexdigest(), mode, pct
