#!/usr/bin/env python3
"""Dump the writable memory of a FROZEN encryptor process (run as root on the NAS).

Freeze first:  kill -STOP <pid>   (do not kill it, do not reboot)
Then:          python3 dump_process_memory.py <pid> <outdir>

Writes outdir/exe.bin (the binary, recoverable even if deleted on disk),
outdir/maps, outdir/mem.bin (all rw-p regions concatenated) and
outdir/mem.idx (one line per region: "<offset in mem.bin> <maps line>").
Python 3.6+, standard library only.
"""
import hashlib, os, shutil, sys


def main(pid, out):
    os.makedirs(out, exist_ok=True)
    state = open('/proc/%s/status' % pid).read()
    if '\nState:\tT' not in state:
        sys.exit('process %s is not stopped; run kill -STOP %s first' % (pid, pid))
    shutil.copyfile('/proc/%s/exe' % pid, os.path.join(out, 'exe.bin'))
    shutil.copyfile('/proc/%s/maps' % pid, os.path.join(out, 'maps'))
    regions = [l.rstrip('\n') for l in open(os.path.join(out, 'maps')) if l.split()[1].startswith('rw')]
    off = 0
    with open('/proc/%s/mem' % pid, 'rb', 0) as mem, \
            open(os.path.join(out, 'mem.bin'), 'wb') as dst, \
            open(os.path.join(out, 'mem.idx'), 'w') as idx:
        for line in regions:
            start, end = (int(x, 16) for x in line.split()[0].split('-'))
            size = end - start
            idx.write('%d %s\n' % (off, line))
            pos = start
            while pos < end:
                n = min(end - pos, 1 << 20)
                try:
                    mem.seek(pos); data = mem.read(n)
                except OSError:
                    data = b''
                dst.write(data + b'\0' * (n - len(data)))  # unreadable pages become zeros
                pos += n
            off += size
    print('regions %d, bytes %d' % (len(regions), off))
    print('exe sha256', hashlib.sha256(open(os.path.join(out, 'exe.bin'), 'rb').read()).hexdigest())


if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
