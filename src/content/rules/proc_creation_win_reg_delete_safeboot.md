---
title: SafeBoot Registry Key Deleted Via Reg.EXE
summary: Detects execution of "reg.exe" commands with the "delete" flag on safe boot registry keys. Often used by attacker to prevent safeboot execution of security products
sigma_id: fc0e89b5-adb0-43c1-b749-c12a10ec37de
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1685
author: Nasreddine Bencherchali (Nextron Systems), Tim Shelton
date: '2022-08-08'
modified: '2023-02-04'
falsepositives:
  - Unlikely
references:
  - https://www.trendmicro.com/en_us/research/22/e/avoslocker-ransomware-variant-abuses-driver-file-to-disable-anti-Virus-scans-log4shell.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_reg_delete_safeboot.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: SafeBoot Registry Key Deleted Via Reg.EXE
id: fc0e89b5-adb0-43c1-b749-c12a10ec37de
related:
    - id: d7662ff6-9e97-4596-a61d-9839e32dee8d
      type: similar
status: test
description: Detects execution of "reg.exe" commands with the "delete" flag on safe boot registry keys. Often used by attacker to prevent safeboot execution of security products
references:
    - https://www.trendmicro.com/en_us/research/22/e/avoslocker-ransomware-variant-abuses-driver-file-to-disable-anti-Virus-scans-log4shell.html
author: Nasreddine Bencherchali (Nextron Systems), Tim Shelton
date: 2022-08-08
modified: 2023-02-04
tags:
    - attack.defense-impairment
    - attack.t1685
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: 'reg.exe'
        - OriginalFileName: 'reg.exe'
    selection_delete:
        CommandLine|contains|all:
            - ' delete '
            - '\SYSTEM\CurrentControlSet\Control\SafeBoot'
    condition: all of selection_*
falsepositives:
    - Unlikely
level: high
```
