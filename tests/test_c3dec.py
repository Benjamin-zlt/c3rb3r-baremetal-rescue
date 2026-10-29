"""Self-contained tests: no sample, no real key, no victim data.

Run: python -m pytest tests/  (or python tests/test_c3dec.py)
"""
import os, struct, sys, tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'tools'))
import c3dec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def test_chacha_core_matches_reference_chacha20():
    # Same core with 20 rounds must equal the library ChaCha20 (64-bit counter + 64-bit nonce).
    key, nonce, ctr = os.urandom(32), os.urandom(8), 7
    data = os.urandom(1000)
    ours, _ = c3dec.chacha(data, key, nonce, ctr, rounds=20)
    ref = Cipher(algorithms.ChaCha20(key, struct.pack('<Q', ctr) + nonce), None).encryptor().update(data)
    assert ours == ref


def test_short_block_consumes_counter():
    _, ctr = c3dec.chacha8(b'x' * 65, b'k' * 32, b'n' * 8, 0)
    assert ctr == 2


def test_segments():
    assert c3dec.segments(1000, 0x24, 0) == [(0, 1000)]
    assert c3dec.segments(3 << 20, 0x26, 0) == [(0, 1 << 20)]
    segs = c3dec.segments(10000, 0x25, 10)
    assert segs == [(0, 400), (4800, 400), (9600, 400)]


def make_encrypted(plain, mode, pct, master, marker=b'\x88\x3c\x03\x09'):
    """Build a synthetic .L0CK3D file the way the sample lays it out."""
    key, nonce = os.urandom(32), os.urandom(8)
    out, ctr, pos = bytearray(), 0, 0
    for off, ln in c3dec.segments(len(plain), mode, pct):
        out += plain[pos:off]
        p = off
        while p < off + ln:
            n = min(off + ln - p, c3dec.CALL)
            enc, ctr = c3dec.chacha8(plain[p:p + n], key, nonce, ctr)
            out += enc; p += n
        pos = off + ln
    out += plain[pos:]
    e = Cipher(algorithms.AES(master[16:]), modes.CBC(master[:16])).encryptor()
    rec = e.update(key + nonce + nonce) + e.finalize()
    footer = bytearray(c3dec.FOOT)
    footer[:48] = rec; footer[568:572] = marker
    footer[572:576] = bytes([mode, pct, 0x20, 0])
    struct.pack_into('<Q', footer, 580, len(plain))
    return bytes(out + footer)


def test_roundtrip_all_modes():
    master = os.urandom(48)
    with tempfile.TemporaryDirectory() as d:
        for mode, pct, size in ((0x24, 0, 70001), (0x25, 10, 3_000_123), (0x26, 0, 2_500_000)):
            plain = os.urandom(size)
            src = os.path.join(d, 'f%x.L0CK3D' % mode)
            open(src, 'wb').write(make_encrypted(plain, mode, pct, master))
            dst = os.path.join(d, 'f%x' % mode)
            c3dec.decrypt_file(src, dst, master)
            assert open(dst, 'rb').read() == plain


def test_wrong_master_is_rejected():
    master = os.urandom(48)
    with tempfile.TemporaryDirectory() as d:
        src = os.path.join(d, 'a.L0CK3D')
        open(src, 'wb').write(make_encrypted(b'hello' * 100, 0x24, 0, master))
        try:
            c3dec.decrypt_file(src, os.path.join(d, 'a'), os.urandom(48))
        except ValueError:
            return
        raise AssertionError('wrong master accepted')


if __name__ == '__main__':
    for name, fn in list(globals().items()):
        if name.startswith('test_'):
            fn(); print('ok', name)
