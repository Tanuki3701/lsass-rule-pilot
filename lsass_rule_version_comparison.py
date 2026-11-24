#!/usr/bin/env python3
"""
Pilot observation: compare three rule versions on the same LSASS access events.
前導觀察：以同一批 LSASS 存取事件，比較三個規則版本的警示數。

Dataset : OTRF Security-Datasets, empire_mimikatz_logonpasswords
          (Empire running Invoke-Mimikatz on Windows; 6,026 events)
Scope   : Sysmon Event ID 10 (ProcessAccess) whose target is lsass.exe.
Rules   : v0 any process accessing lsass.exe
          v1 v0, excluding events whose source is svchost.exe
          v2 v0, keeping only events with PROCESS_VM_READ (0x0010) in GrantedAccess

Labels  : the PowerShell access is provisionally labelled "attack" from the dataset
          description; the others are provisionally "benign". This is NOT verified
          event by event, and a single run on a single dataset is only a pilot.

Usage   : python3 lsass_rule_version_comparison.py             # download the dataset
          python3 lsass_rule_version_comparison.py --local FILE.json   # use a local copy
"""
import argparse
from io import BytesIO
from zipfile import ZipFile

import pandas as pd
import requests

URL = ('https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/'
       'atomic/windows/credential_access/host/empire_mimikatz_logonpasswords.zip')
PROCESS_VM_READ = 0x0010


def load_events(local_path=None):
    """Return the raw event table (one JSON event per line)."""
    if local_path:
        return pd.read_json(local_path, lines=True)
    zf = ZipFile(BytesIO(requests.get(URL, timeout=60).content))
    with zf.open(zf.namelist()[0]) as f:
        return pd.read_json(f, lines=True)


def lsass_access_events(df):
    """Sysmon Event ID 10 (ProcessAccess) events whose target image is lsass.exe."""
    sm = df[(df['Channel'].str.contains('Sysmon', na=False)) & (df['EventID'] == 10)
            & (df['TargetImage'].str.contains('lsass', case=False, na=False))].copy()
    sm['GrantedAccessInt'] = sm['GrantedAccess'].apply(lambda x: int(x, 16))
    # Provisional label (see module docstring): PowerShell access = attack.
    sm['is_attack'] = sm['SourceImage'].str.lower().str.contains('powershell')
    return sm


def rule_versions(sm):
    """The three rule versions, each as a filtered view of the same events."""
    return {
        'v0 任何處理程序存取 lsass': sm,
        'v1 排除 svchost.exe': sm[~sm['SourceImage'].str.lower().str.endswith('svchost.exe')],
        'v2 權限含 PROCESS_VM_READ(0x0010)': sm[(sm['GrantedAccessInt'] & PROCESS_VM_READ) != 0],
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[1])
    ap.add_argument('--local', help='path to an already extracted .json dataset file')
    ap.add_argument('--verbose', action='store_true', help='also print dataset size')
    args = ap.parse_args()

    df = load_events(args.local)
    sm = lsass_access_events(df)
    if args.verbose:
        print(f'total events: {len(df)}; Sysmon ProcessAccess to lsass.exe: {len(sm)}\n')
    print(sm[['@timestamp', 'SourceImage', 'GrantedAccess', 'is_attack']].to_string())
    print()
    for name, r in rule_versions(sm).items():
        tp = int(r['is_attack'].sum())
        fp = len(r) - tp
        print(f'{name}: 警示 {len(r)}，攻擊 {tp}，誤報 {fp}')


if __name__ == '__main__':
    main()
