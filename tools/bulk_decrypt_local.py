#!/usr/bin/env python3
"""Bulk recovery run directly on the NAS (no network round trip).

    python3 bulk_decrypt_local.py --root /volume1/SHARE --list files.lst \
        --master master.bin --marker 883c0309 [--state DIR]

files.lst: paths of .L0CK3D files relative to --root, one per line, in the
order you want them restored (most important folders first). Build it with
    cd /volume1/SHARE && find . -name '*.L0CK3D' | sed 's|^\\./||' > files.lst

For each X.L0CK3D, writes the plaintext to X next to it (via X.c3part, then a
rename). Never overwrites: a name clash becomes X.解密.ext. The .L0CK3D file is
left untouched so the run can be repeated or audited. Re-runnable: finished
paths go to <state>/decrypt.done. Progress every 500 files in <state>/decrypt.log.
Start it detached so it survives the ssh session:
    setsid nohup python3 bulk_decrypt_local.py ... > run.out 2>&1 < /dev/null &
"""
import argparse, os, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'lib')); sys.path.insert(0, HERE)  # lib/ = unpacked numpy wheel
import c3dec

PART = '.c3part'


class Run:
    def __init__(self, a):
        self.root, self.list = a.root, a.list
        self.master = open(a.master, 'rb').read()
        self.marker = bytes.fromhex(a.marker)
        os.makedirs(a.state, exist_ok=True)
        self.done = os.path.join(a.state, 'decrypt.done')
        self.logf = os.path.join(a.state, 'decrypt.log')

    def log(self, msg):
        with open(self.logf, 'a', encoding='utf-8') as f:
            f.write(time.strftime('%F %T ') + msg + '\n')

    def recover(self, rel):
        src = os.path.join(self.root, rel)
        if not os.path.isfile(src):
            return 'MISSING'
        with open(src, 'rb') as f:
            f.seek(-c3dec.FOOT, 2); marker = f.read(c3dec.FOOT)[568:572]
        if marker != self.marker:
            return 'FAIL foreign marker ' + marker.hex()
        target = src[:-len('.L0CK3D')]
        res = 'OK'
        if os.path.lexists(target):
            stem, ext = os.path.splitext(target)
            target = stem + '.解密' + ext; res = 'CONFLICT'
            if os.path.lexists(target):
                return 'SKIP exists'
        tmp = target + PART
        if os.path.lexists(tmp):
            os.remove(tmp)
        try:
            c3dec.decrypt_file(src, tmp, self.master)
            st = os.stat(src)
            os.utime(tmp, (st.st_atime, st.st_mtime))
            if os.path.lexists(target):
                os.remove(tmp); return 'SKIP raced'
            os.rename(tmp, target)
        except Exception as ex:
            if os.path.lexists(tmp):
                os.remove(tmp)
            return 'FAIL ' + str(ex)
        return res

    def main(self):
        done = set(open(self.done, encoding='utf-8').read().splitlines()) if os.path.exists(self.done) else set()
        todo = [l for l in open(self.list, encoding='utf-8').read().splitlines() if l and l not in done]
        self.log('START %d to do, %d done' % (len(todo), len(done)))
        stats, t0, nbytes = {}, time.time(), 0
        with open(self.done, 'a', encoding='utf-8') as d:
            for n, rel in enumerate(todo, 1):
                try:
                    res = self.recover(rel)
                except Exception as ex:
                    res = 'FAIL ' + str(ex)
                key = res.split()[0]; stats[key] = stats.get(key, 0) + 1
                if key != 'OK':
                    self.log('%s | %s' % (res, rel))
                if key in ('OK', 'CONFLICT'):
                    try: nbytes += os.path.getsize(os.path.join(self.root, rel))
                    except OSError: pass
                if key != 'MISSING':
                    d.write(rel + '\n'); d.flush()
                if n % 500 == 0:
                    el = time.time() - t0
                    self.log('PROGRESS %d/%d %.1fGB %.0fMB/s %s' % (
                        n, len(todo), nbytes / 2**30, nbytes / 2**20 / max(el, 1), stats))
        self.log('ALL DONE %s' % stats)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--root', required=True)
    p.add_argument('--list', required=True)
    p.add_argument('--master', required=True)
    p.add_argument('--marker', required=True, help='4-byte session marker at footer offset 568, hex')
    p.add_argument('--state', default='.')
    Run(p.parse_args()).main()
