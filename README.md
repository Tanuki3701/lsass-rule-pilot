# lsass-rule-pilot

English | [繁體中文](README.zh-TW.md)

A small pilot observation: **how many alerts, true detections and false positives do three versions of a detection rule produce on the same LSASS access events?**

This is the pilot behind a research question: *when a detection rule is adjusted to reduce false positives, how much detection capability is lost, and can the adjustment be evaded?*

> **Status: pilot only.** The baseline is one dataset, one attack run, four events; an extended check adds 10 attack executions (see below). Both only show that the question is worth studying. Neither estimates how well any rule performs.

## What it does

1. Loads the public [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) `empire_mimikatz_logonpasswords` dataset (Empire running Invoke-Mimikatz on Windows, 6,026 events), either by downloading it or from a local copy.
2. Keeps Sysmon Event ID 10 (ProcessAccess) events whose target is `lsass.exe` (4 events).
3. Applies three rule versions to those same events and prints alerts, attack events and false positives for each.

| Version | Condition | Alerts | Attack | False positives |
|---|---|---|---|---|
| v0 | any process accessing `lsass.exe` | 4 | 1 | 3 |
| v1 | v0, excluding events whose source is `svchost.exe` | 1 | 1 | 0 |
| v2 | v0, keeping only `GrantedAccess` with `PROCESS_VM_READ` (0x0010) | 1 | 1 | 0 |

## Run it

```bash
pip install -r requirements.txt
python3 lsass_rule_version_comparison.py                   # downloads the dataset
python3 lsass_rule_version_comparison.py --local FILE.json # or use an extracted local copy
python3 lsass_rule_version_comparison.py --verbose         # also prints dataset size
```

The output should match [`expected_output.txt`](expected_output.txt). Printed labels are in Chinese.

## Extended observation: 10 attack executions

To check that the pattern is not an artefact of one recording, `lsass_rule_multi_run.py` applies the same v0–v2 rules to 10 attack executions from the same project (8 technique groups, such as nanodump, comsvcs MiniDump, Dumpert, SharpDump, procdump, Metasploit payload and a renamed Mimikatz; commit `d9d40ef`). The unit is **one attack execution**, not one event.

```bash
python3 lsass_rule_multi_run.py --root PATH/TO/Security-Datasets/datasets   # local checkout at the pinned commit
python3 lsass_rule_multi_run.py                                            # or download the 10 zips
python3 lsass_rule_multi_run.py --events --hashes                          # per-event detail, zip SHA-256
```

Output should match [`expected_output_multi_run.txt`](expected_output_multi_run.txt).

| | v0 | v1 (no svchost) | v2 (needs VM_READ) |
|---|---|---|---|
| Attack-related events alerted (26 in total) | 26 | 26 | 19 |
| Executions with at least one alert (of 10) | 10 | 10 | 10 |
| Alerts on unlabelled events (not verified) | 2,551 | 1,857 | 7 |

What it shows: v2 drops 7 of 26 attack-related events (their access masks lack VM_READ) yet every execution still raises at least one alert, so event-level and execution-level results differ. What it cannot show: with only 10 executions the Wilson 95% lower bound for 10/10 is about 72%, and v1 vs v2 cannot be judged on false positives because the non-attack events are unverified system activity.

**How events are labelled.** An event is "attack-related" only if the source process's own Sysmon Event ID 1 record (matched by ProcessGuid) contains the tool name or command-line argument listed per run in the script. The label does not use any rule condition, so it is not circular with v1 or v2. Every other lsass event is "unlabelled" and is deliberately **not** called a false positive.

**Not included.** `empire_mimikatz_logonpasswords` (the baseline above) and other Empire recordings have no process-creation events to verify labels, so they stay provisional. `rdp_interactive_taskmanager_lsass_dump` needs manual review (Task Manager also touches lsass routinely). `empire_mimikatz_sam_access` has 1,477 accesses by one process within 0.44 s and would count as one execution. Several payload accesses (0x1000/0x1400) are labelled attack-related from the process evidence, but whether each one is part of the credential theft has not been checked. These are listed for transparency; none are used above.

## Reproducibility notes

- Run on 2026-11-24 with Python 3.13.18, pandas 3.0.5, requests 2.34.2.
- Dataset zip (downloaded from the `master` branch): SHA-256 `bb4c057b62d781be5426e011872ba1a15070c07afbb24848a14458f4b22b06fb`, 716,749 bytes. If the upstream file changes, compare this hash first.
- Total events: 6,026. Sysmon ProcessAccess events targeting `lsass.exe`: 4.
- The dataset is not stored in this repository; please obtain it from the upstream project and follow its license.

## Limitations

- **Labels are provisional.** The PowerShell access is labelled "attack" from the dataset description; the other three events are labelled "benign". Each event has not been verified against its full context.
- **Tiny sample.** Four events from one attack run; no confidence interval or generalisation is claimed.
- **Name-based exclusions can be evaded.** v1 excludes by process name, which an attacker can rename or spoof. The pilot does not test evasion.
- **No normal-workload data.** False positives here come only from the few benign events inside the attack recording, not from real or simulated everyday activity.

## Planned next steps (research, not part of this script)

- Add a v3 rule using multiple fields (context conditions).
- Split data into a development set (used to design and tune v0–v3) and a held-out evaluation set that is never used for tuning.
- Add evasion variants and a normal-workload environment, and keep a reproducible tuning log.
