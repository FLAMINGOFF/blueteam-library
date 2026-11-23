---
title: Renamed AutoHotkey.EXE Execution
summary: Detects execution of a renamed autohotkey.exe binary based on PE metadata fields
sigma_id: 0f16d9cf-0616-45c8-8fad-becc11b5a41c
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques: []
author: Nasreddine Bencherchali
date: '2023-02-07'
falsepositives:
  - Unknown
references:
  - https://www.autohotkey.com/download/
  - https://thedfirreport.com/2023/02/06/collect-exfiltrate-sleep-repeat/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_renamed_autohotkey.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Renamed AutoHotkey.EXE Execution
id: 0f16d9cf-0616-45c8-8fad-becc11b5a41c
status: test
description: Detects execution of a renamed autohotkey.exe binary based on PE metadata fields
references:
    - https://www.autohotkey.com/download/
    - https://thedfirreport.com/2023/02/06/collect-exfiltrate-sleep-repeat/
author: Nasreddine Bencherchali
date: 2023-02-07
tags:
    - attack.stealth
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Product|contains: 'AutoHotkey'
        - Description|contains: 'AutoHotkey'
        - OriginalFileName:
              - 'AutoHotkey.exe'
              - 'AutoHotkey.rc'
    filter:
        - Image|endswith:
              - '\AutoHotkey.exe'
              - '\AutoHotkey32.exe'
              - '\AutoHotkey32_UIA.exe'
              - '\AutoHotkey64.exe'
              - '\AutoHotkey64_UIA.exe'
              - '\AutoHotkeyA32.exe'
              - '\AutoHotkeyA32_UIA.exe'
              - '\AutoHotkeyU32.exe'
              - '\AutoHotkeyU32_UIA.exe'
              - '\AutoHotkeyU64.exe'
              - '\AutoHotkeyU64_UIA.exe'
        - Image|contains: '\AutoHotkey'
    condition: selection and not filter
falsepositives:
    - Unknown
level: medium
```
