#!/usr/bin/env python3
"""
Extended pilot: apply the same three rule versions to 10 attack executions
from public OTRF Security-Datasets recordings.
擴充前導：把同樣三個規則版本套用到 10 次公開資料集中的攻擊執行。

Unit    : one attack execution (= one dataset recording), not one event.
Events  : Sysmon Event ID 10 (ProcessAccess) whose target is lsass.exe.
Rules   : v0 any process accessing lsass.exe
          v1 v0, excluding events whose source image is svchost.exe
          v2 v0, keeping only GrantedAccess that contains PROCESS_VM_READ (0x0010)

Labels  : an event is "attack-related" only if the SOURCE process's own Sysmon
          Event ID 1 record (matched by ProcessGuid) matches the marker listed for
          that run in RUNS below (tool name or command-line argument). The label
          does not use the rule conditions, so it is not circular with v1 / v2.
          All other lsass events are "unlabelled" (not verified). They are NOT
          called false positives, because their context was not checked.

Usage   : python3 lsass_rule_multi_run.py --root PATH/TO/Security-Datasets/datasets
          python3 lsass_rule_multi_run.py            # downloads the 10 zips (pinned commit)
"""
import argparse
import hashlib
import json
import math
import os
import re
import urllib.request
from io import BytesIO
from zipfile import ZipFile

COMMIT = 'd9d40ef123d2c87d5d3df28c96bcab4f0faccc87'
BASE = f'https://raw.githubusercontent.com/OTRF/Security-Datasets/{COMMIT}/datasets/'
PROCESS_VM_READ = 0x0010

# (run id, technique group, dataset path, marker regex on the source process,
#  evidence). The marker is searched in the source process's Image + CommandLine
# taken from its Sysmon Event ID 1 record.
RUNS = [
    ('R01', 'nanodump', 'compound/LSASS_campaign_07/metasploit_nanodump_lsass_memory_dump.zip',
     r'nanodump', 'command line: nanodump --write'),
    ('R02', 'comsvcs MiniDump', 'compound/LSASS_campaign_03/metasploit_comsvcs_lsass_memory_dump.zip',
     r'comsvcs\.dll\s+MiniDump|winx64_payload', 'command line comsvcs.dll MiniDump; attack payload process'),
    ('R03', 'Dumpert', 'compound/LSASS_campaign_06/metasploit_outflank-dumpert_lsass_memory_dump.zip',
     r'outflank-dumpert', 'command line: Outflank-Dumpert.exe'),
    ('R04', 'SharpDump', 'compound/LSASS_campaign_05/metasploit_sharpdump_lsass_memory_dump.zip',
     r'sharpdump', 'command line: SharpDump.exe'),
    ('R05', 'procdump', 'compound/LSASS_campaign_02/metasploit_procdump_lsass_memory_dump.zip',
     r'procdump', 'command line: procdump -ma lsass.exe'),
    ('R06', 'payload (logonpasswords)', 'compound/LSASS_campaign_01/metasploit_logonpasswords_lsass_memory_dump.zip',
     r'winx64_payload', 'attack payload process'),
    ('R07', 'payload (out-minidump)', 'compound/LSASS_campaign_04/metasploit_out-minidump_lsass_memory_dump.zip',
     r'winx64_payload', 'attack payload process'),
    ('R08', 'Dumpert', 'atomic/windows/credential_access/host/cmd_lsass_memory_dumpert_syscalls.zip',
     r'outflank-dumpert', 'command line: Outflank-Dumpert.exe'),
    ('R09', 'comsvcs MiniDump', 'atomic/windows/credential_access/host/psh_lsass_memory_dump_comsvcs.zip',
     r'comsvcs\.dll\s+MiniDump', 'command line comsvcs.dll MiniDump'),
    ('R10', 'renamed Mimikatz', 'compound/apt29/day2/apt29_evals_day2_manual.zip',
     r'sekurlsa::|lsadump::', 'command-line arguments sekurlsa:: / lsadump:: (binary renamed m.exe)'),
]


def read_zip(rel, root):
    if root:
        data = open(os.path.join(root, rel), 'rb').read()
    else:
        with urllib.request.urlopen(BASE + rel, timeout=120) as r:
            data = r.read()
    return data, hashlib.sha256(data).hexdigest()


def sysmon_events(data):
    """Yield Sysmon event dicts from every .json file inside the zip."""
    with ZipFile(BytesIO(data)) as z:
        for n in z.namelist():
            low = n.lower()
            if n.endswith('/') or n.startswith('__MACOSX') or '/._' in n or not low.endswith('.json'):
                continue
            with z.open(n) as f:
                for line in f:
                    line = line.strip()
                    if not line.startswith(b'{'):
                        continue
                    try:
                        d = json.loads(line)
                    except ValueError:
                        continue
                    if 'Sysmon' in str(d.get('Channel', '')):
                        yield d


def analyse(data, marker):
    procs, lsass = {}, []
    for d in sysmon_events(data):
        try:
            eid = int(d.get('EventID', -1))
        except (TypeError, ValueError):
            continue
        if eid == 1:
            procs[d.get('ProcessGuid')] = f"{d.get('Image', '')} {d.get('CommandLine', '')}"
        elif eid == 10 and str(d.get('TargetImage', '')).lower().endswith('lsass.exe'):
            lsass.append(d)
    pat = re.compile(marker, re.I)
    rows = []
    for d in lsass:
        src = str(d.get('SourceImage', ''))
        access = int(d.get('GrantedAccess', '0x0'), 16)
        ctx = procs.get(d.get('SourceProcessGUID'), '')
        rows.append(dict(
            attack=bool(pat.search(ctx)),
            v0=True,
            v1=not src.lower().endswith('svchost.exe'),
            v2=(access & PROCESS_VM_READ) != 0,
            src=src.split('\\')[-1], access=d.get('GrantedAccess')))
    return rows


def wilson_lower(k, n, z=1.96):
    p = k / n
    return (p + z * z / (2 * n) - z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / (1 + z * z / n)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[1])
    ap.add_argument('--root', help='local .../Security-Datasets/datasets (checkout at the pinned commit)')
    ap.add_argument('--events', action='store_true', help='also list every attack-related event')
    ap.add_argument('--hashes', action='store_true', help='also print each zip SHA-256 and the label evidence')
    args = ap.parse_args()

    print(f'commit {COMMIT[:7]}\n')
    hdr = f"{'run':4} {'group':25} {'attack evts':>11} {'v0':>4} {'v1':>4} {'v2':>4}  {'run caught (v0/v1/v2)':22} {'other alerts v0/v1/v2':>22}"
    print(hdr)
    tot = dict(a=0, v0=0, v1=0, v2=0, o0=0, o1=0, o2=0)
    caught = dict(v0=0, v1=0, v2=0)
    for rid, group, rel, marker, why in RUNS:
        data, sha = read_zip(rel, args.root)
        rows = analyse(data, marker)
        att = [r for r in rows if r['attack']]
        oth = [r for r in rows if not r['attack']]
        n = len(att)
        c = {v: sum(r[v] for r in att) for v in ('v0', 'v1', 'v2')}
        o = {v: sum(r[v] for r in oth) for v in ('v0', 'v1', 'v2')}
        flags = '/'.join('Y' if c[v] else 'N' for v in ('v0', 'v1', 'v2'))
        print(f"{rid:4} {group:25} {n:>11} {c['v0']:>4} {c['v1']:>4} {c['v2']:>4}  {flags:22} {o['v0']:>6}/{o['v1']}/{o['v2']}")
        tot['a'] += n
        for v in ('v0', 'v1', 'v2'):
            tot[v] += c[v]
            tot['o' + v[1]] += o[v]
            caught[v] += bool(c[v])
        if args.events:
            for r in att:
                print(f"       {r['src']:22} {r['access']:>9}  v1={'alert' if r['v1'] else '-'}  v2={'alert' if r['v2'] else '-'}")
        if args.hashes:
            print(f'       sha256 {sha}  evidence: {why}')
    print()
    print(f"attack-related events : {tot['a']}  (alerts v0/v1/v2 = {tot['v0']}/{tot['v1']}/{tot['v2']})")
    print(f"runs with >=1 alert   : v0 {caught['v0']}/10, v1 {caught['v1']}/10, v2 {caught['v2']}/10")
    print(f"unlabelled-event alerts: v0 {tot['o0']}, v1 {tot['o1']}, v2 {tot['o2']}  (not verified; NOT counted as false positives)")
    for v in ('v0', 'v1', 'v2'):
        print(f"Wilson 95% lower bound, run-level {v}: {caught[v]}/10 -> {wilson_lower(caught[v], 10):.1%}")


if __name__ == '__main__':
    main()
