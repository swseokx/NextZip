"""Corpus harness: extract every archive with NextZip (`nz x`) and 7-Zip
(`7z x`) and compare success.

usage: python -I bench/corpus/compare.py --nz <nz.exe> --7z <7z.exe>
           --out <results.tsv> [--list <paths.txt>] <dir-or-file>...

An archive counts as a success for a tool when the tool exits 0 and
writes at least one file. For archives both tools extract, the extracted
trees are compared (file count, total bytes, CRC-32 of every file); for
tools that name single-stream output differently, a one-file tree is
compared by content only. Each archive gets a 60 s time limit per tool.

Columns: archive, size, nz (ok/FAIL/timeout), 7z, same-content
(yes/no/-), nz files, 7z files, nz error (first line).
Nothing here modifies the inputs; outputs go to a temp directory.
"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import zlib

SKIP_EXT = {'.tsv', '.md', '.rs', '.txt', '.c', '.h', '.py', '.json'}


def tree(root):
    out = {}
    for dp, _, fs in os.walk(root):
        for f in fs:
            p = os.path.join(dp, f)
            rel = os.path.relpath(p, root).replace(os.sep, '/')
            if os.path.islink(p):
                # 7-Zip recreates symbolic links; NextZip does not (spec 9).
                continue
            try:
                with open(p, 'rb') as fh:
                    d = fh.read()
            except OSError:
                continue
            out[rel] = (len(d), zlib.crc32(d) & 0xffffffff)
    return out


def run(cmd, timeout=60):
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout,
                           stdin=subprocess.DEVNULL)
        err = (r.stderr or r.stdout).decode('utf-8', 'replace').strip()
        return ('ok' if r.returncode == 0 else 'FAIL'), err
    except subprocess.TimeoutExpired:
        return 'timeout', 'timeout'


def inputs(paths):
    for p in paths:
        if os.path.isfile(p):
            yield p
            continue
        for dp, _, fs in os.walk(p):
            for f in sorted(fs):
                if os.path.splitext(f)[1].lower() in SKIP_EXT:
                    continue
                yield os.path.join(dp, f)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--nz', required=True)
    ap.add_argument('--7z', dest='sz', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--list', help='file with one archive path per line')
    ap.add_argument('paths', nargs='*')
    a = ap.parse_args()
    if a.list:
        with open(a.list, encoding='utf-8') as f:
            a.paths += [l.strip() for l in f if l.strip()]
    rows = []
    for p in inputs(a.paths):
        if not os.path.isfile(p):
            continue
        # Deep trees from long-path tests outlive MAX_PATH; the cleanup
        # retries with the \\?\ prefix below.
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as t:
            o1, o2 = os.path.join(t, 'nz'), os.path.join(t, 'sz')
            s1, e1 = run([a.nz, 'x', '-q', '-o:' + o1, p])
            s2, _ = run([a.sz, 'x', '-y', '-p-', '-o' + o2, p])
            t1 = tree(o1) if os.path.isdir(o1) else {}
            t2 = tree(o2) if os.path.isdir(o2) else {}
            # 7-Zip opens one layer at a time (x.tar.gz -> x.tar, RPM ->
            # cpio); NextZip opens the inner tar/cpio too. Follow 7-Zip one
            # layer further so the trees compare.
            if len(t2) == 1 and not any(k.lower().endswith(('.tar', '.cpio')) for k in t1):
                (only,) = t2
                if only.lower().endswith(('.tar', '.cpio')):
                    o3 = os.path.join(t, 'sz2')
                    if run([a.sz, 'x', '-y', '-o' + o3, os.path.join(o2, only)])[0] == 'ok':
                        t2 = tree(o3)
            t2.pop('[TOC].xml', None)
            if s1 == 'ok' and not t1:
                s1 = 'FAIL'
                e1 = e1 or 'no files'
            if s2 == 'ok' and not t2:
                s2 = 'FAIL'
            same = '-'
            if s1 == 'ok' and s2 == 'ok':
                if len(t1) == 1 and len(t2) == 1:
                    same = 'yes' if list(t1.values()) == list(t2.values()) else 'no'
                else:
                    same = 'yes' if t1 == t2 else 'no'
            rows.append((p, os.path.getsize(p), s1, s2, same, len(t1), len(t2),
                         e1.splitlines()[0][:160] if s1 != 'ok' and e1 else ''))
            print('\t'.join(map(str, rows[-1])), file=sys.stderr)
            if os.name == 'nt':
                shutil.rmtree('\\\\?\\' + os.path.abspath(t), ignore_errors=True)
    with open(a.out, 'w', encoding='utf-8') as f:
        f.write('archive\tsize\tnz\t7z\tsame\tnz_files\t7z_files\tnz_error\n')
        for r in rows:
            f.write('\t'.join(map(str, r)) + '\n')
    n = len(rows)
    ok1 = sum(r[2] == 'ok' for r in rows)
    ok2 = sum(r[3] == 'ok' for r in rows)
    both = sum(r[2] == 'ok' and r[3] == 'ok' for r in rows)
    only7 = sum(r[2] != 'ok' and r[3] == 'ok' for r in rows)
    onlynz = sum(r[2] == 'ok' and r[3] != 'ok' for r in rows)
    diff = sum(r[4] == 'no' for r in rows)
    print(f'archives {n}: nz ok {ok1}, 7z ok {ok2}, both {both}, '
          f'only 7z {only7}, only nz {onlynz}, content differs {diff}')


main()
