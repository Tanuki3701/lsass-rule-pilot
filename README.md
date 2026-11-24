# lsass-rule-pilot

A small pilot observation: **how many alerts, true detections and false positives do three versions of a detection rule produce on the same LSASS access events?**
一個小型前導觀察：同一批 LSASS 存取事件，三個規則版本各產生多少警示、檢出與誤報。

This is the pilot behind my research question: *when a detection rule is adjusted to reduce false positives, how much detection capability is lost, and can the adjustment be evaded?*
這是我研究問題的前導觀察：規則為了降低誤報而調整後，會損失多少檢出能力、是否容易被規避。

> **Status: pilot only.** One dataset, one attack run, four events. It shows that the question is worth studying. It does **not** estimate how well any rule performs.
> **僅為前導觀察。** 單一資料集、一次攻擊執行、4 筆事件，只用來確認此現象值得進一步研究，不作為正式效果結論。

## What it does

1. Loads the public [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) `empire_mimikatz_logonpasswords` dataset (Empire running Invoke-Mimikatz on Windows, 6,026 events), either by downloading it or from a local copy.
2. Keeps Sysmon Event ID 10 (ProcessAccess) events whose target is `lsass.exe` (4 events).
3. Applies three rule versions to those same events and prints alerts, attack events and false positives for each.

| Version | Condition | Alerts | Attack | False positives |
|---|---|---|---|---|
| v0 | any process accessing `lsass.exe` | 4 | 1 | 3 |
| v1 | v0, excluding events whose source is `svchost.exe` | 1 | 1 | 0 |
| v2 | v0, keeping only `GrantedAccess` with `PROCESS_VM_READ` (0x0010) | 1 | 1 | 0 |

(中文：v0 為任何程序存取 lsass.exe；v1 排除來源為 svchost.exe 的事件；v2 只保留存取權限包含 PROCESS_VM_READ 的事件。)

## Run it

```bash
pip install -r requirements.txt
python3 lsass_rule_version_comparison.py                  # downloads the dataset
python3 lsass_rule_version_comparison.py --local FILE.json # or use an extracted local copy
python3 lsass_rule_version_comparison.py --verbose        # also prints dataset size
```

The output should match [`expected_output.txt`](expected_output.txt). Printed labels are in Chinese (the same output used in my application materials).

## Reproducibility notes

- Run on 2026-11-24 with Python 3.13.18, pandas 3.0.5, requests 2.34.2.
- Dataset zip (downloaded from the `master` branch): SHA-256 `bb4c057b62d781be5426e011872ba1a15070c07afbb24848a14458f4b22b06fb`, 716,749 bytes. If the upstream file changes, compare this hash first.
- Total events: 6,026. Sysmon ProcessAccess events targeting `lsass.exe`: 4.
- The dataset is not stored in this repository; please obtain it from the upstream project and follow its license.

## Limitations

- **Labels are provisional.** The PowerShell access is labelled "attack" from the dataset description; the other three events are labelled "benign". I have not verified each event against its full context.
- **Tiny sample.** Four events from one attack run; no confidence interval or generalisation is claimed.
- **Name-based exclusions can be evaded.** v1 excludes by process name, which an attacker can rename or spoof. The pilot does not test evasion.
- **No normal-workload data.** False positives here come only from the few benign events inside the attack recording, not from real or simulated everyday activity.

## Planned next steps (research, not part of this script)

- Add a v3 rule using multiple fields (context conditions).
- Split data into a development set (used to design and tune v0–v3) and a held-out evaluation set that is never used for tuning.
- Add evasion variants and a normal-workload environment, and keep a reproducible tuning log.

## Author

Luz Luo (羅子歆), Department of Information Management, National Taiwan University of Science and Technology.
