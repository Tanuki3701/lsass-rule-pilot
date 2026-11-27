# lsass-rule-pilot

[English](README.md) | 繁體中文

一個小型前導觀察：**同一批 LSASS 存取事件，三個版本的偵測規則各產生多少警示、檢出與誤報？**

這是以下研究問題的前導觀察：*偵測規則為了降低誤報而調整後，會損失多少偵測能力？這種調整是否容易被規避？*

> **僅為前導觀察。** 基準為單一資料集、一次攻擊執行、4 筆事件；另有擴充觀察（10 次攻擊執行，見下）。兩者都只用來確認此現象值得進一步研究，**不**用來評估任何規則的實際效果。

## 程式功能

1. 載入公開的 [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) `empire_mimikatz_logonpasswords` 資料集（在 Windows 上以 Empire 執行 Invoke-Mimikatz，共 6,026 筆事件），可自動下載或使用本機副本。
2. 保留目標為 `lsass.exe` 的 Sysmon Event ID 10（ProcessAccess）事件，共 4 筆。
3. 對同一批事件套用三個規則版本，並印出各版本的警示數、攻擊事件數與誤報數。

| 版本 | 條件 | 警示 | 攻擊 | 誤報 |
|---|---|---|---|---|
| v0 | 任何程序存取 `lsass.exe` | 4 | 1 | 3 |
| v1 | v0，排除來源為 `svchost.exe` 的事件 | 1 | 1 | 0 |
| v2 | v0，只保留 `GrantedAccess` 含 `PROCESS_VM_READ`（0x0010）的事件 | 1 | 1 | 0 |

## 執行方式

```bash
pip install -r requirements.txt
python3 lsass_rule_version_comparison.py                   # 自動下載資料集
python3 lsass_rule_version_comparison.py --local FILE.json # 或使用已解壓縮的本機檔案
python3 lsass_rule_version_comparison.py --verbose         # 另外印出資料集大小
```

輸出應與 [`expected_output.txt`](expected_output.txt) 一致。程式輸出的標籤為中文。

## 擴充觀察：10 次攻擊執行

為確認上述現象不是單一錄製的偶然，`lsass_rule_multi_run.py` 把同樣的 v0–v2 規則套用到同一專案的 10 次攻擊執行（8 個技術群組，例如 nanodump、comsvcs MiniDump、Dumpert、SharpDump、procdump、Metasploit 載荷與更名 Mimikatz；commit `d9d40ef`）。統計單位是**一次攻擊執行**，不是單一事件。

```bash
python3 lsass_rule_multi_run.py --root PATH/TO/Security-Datasets/datasets   # 本機 checkout（固定 commit）
python3 lsass_rule_multi_run.py                                            # 或自動下載 10 個 zip
python3 lsass_rule_multi_run.py --events --hashes                          # 逐筆事件、zip 的 SHA-256
```

輸出應與 [`expected_output_multi_run.txt`](expected_output_multi_run.txt) 一致（標籤為英文）。

| | v0 | v1（排除 svchost） | v2（需含 VM_READ） |
|---|---|---|---|
| 攻擊相關事件有警示（共 26 筆） | 26 | 26 | 19 |
| 至少有 1 筆警示的攻擊執行（共 10 次） | 10 | 10 | 10 |
| 未標記事件的警示（未驗證） | 2,551 | 1,857 | 7 |

能看出的：v2 漏掉 26 筆攻擊相關事件中的 7 筆（存取權限不含 VM_READ），但每次攻擊執行仍至少觸發一筆警示，可見「以事件計」與「以攻擊執行計」的結果不同。看不出的：只有 10 次執行，10/10 的 Wilson 95% 下界約 72%；且非攻擊事件屬未驗證的系統活動，無法據此判斷 v1 與 v2 的誤報優劣。

**標記方式。** 只有當來源程序自己的 Sysmon Event ID 1 紀錄（以 ProcessGuid 對應）含有程式中各次執行所列的工具名稱或命令列參數，該事件才標為「攻擊相關」。標記不使用任何規則條件，因此與 v1、v2 不會形成循環論證。其餘 lsass 事件為「未標記」，刻意**不**稱為誤報。

**未納入。** 上方基準使用的 `empire_mimikatz_logonpasswords` 與其他 Empire 錄製沒有程序建立事件可佐證，標記維持暫定；`rdp_interactive_taskmanager_lsass_dump` 需人工判定（工作管理員平常也會存取 lsass）；`empire_mimikatz_sam_access` 由單一程序在 0.44 秒內存取 1,477 次，只能算一次執行。若干攻擊載荷程序的存取（0x1000/0x1400）依程序證據標為攻擊相關，但每一筆是否屬於憑證竊取行為尚未逐筆確認。以上僅為揭露，皆未用於上表。

## 可重現性說明

- 執行日期 2026-11-24；Python 3.13.18、pandas 3.0.5、requests 2.34.2。
- 資料集 zip（取自 `master` 分支）：SHA-256 `bb4c057b62d781be5426e011872ba1a15070c07afbb24848a14458f4b22b06fb`，716,749 bytes。若上游檔案變動，請先比對此雜湊值。
- 事件總數 6,026 筆；目標為 `lsass.exe` 的 Sysmon ProcessAccess 事件 4 筆。
- 本倉庫不含資料集，請自上游專案取得並遵守其授權。

## 限制

- **標記為暫定。** 依資料集說明，將 PowerShell 的存取標為「攻擊」，其餘三筆標為「正常」，尚未逐筆對照完整上下文驗證。
- **樣本極小。** 僅單次攻擊執行的 4 筆事件，不提供信賴區間，也不主張可推廣。
- **以名稱排除可被規避。** v1 依程序名稱排除，攻擊者可更名或偽造；本前導觀察未測試規避情境。
- **缺乏正常負載資料。** 這裡的誤報僅來自攻擊錄製中的少數正常事件，並非真實或模擬的日常活動。

## 後續規劃（屬研究內容，不在本程式內）

- 新增使用多個欄位（情境條件）的 v3 規則。
- 將資料分為開發集（用於設計與調校 v0–v3）與從不參與調校的保留評估集。
- 加入規避變體與正常負載環境，並保留可重現的調校紀錄。
