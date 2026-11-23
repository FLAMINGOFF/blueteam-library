---
title: Suspicious MSHTA Child Process
summary: Detects a suspicious process spawning from an "mshta.exe" process, which could be indicative of a malicious HTA script execution
sigma_id: 03cc0c25-389f-4bf8-b48d-11878079f1ca
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1218.005
author: Michael Haag
date: '2019-01-16'
modified: '2023-02-06'
falsepositives:
  - Printer software / driver installations
  - HP software
references:
  - https://web.archive.org/web/20150906062519/https://www.trustedsec.com/july-2015/malicious-htas/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_mshta_susp_child_processes.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
title_zh: mshta.exe 派生可疑子进程
summary_zh: 检测由 mshta.exe 派生的可疑进程，可能表示恶意 HTA 脚本正在执行。
featured: true
---

```yaml
title: Suspicious MSHTA Child Process
id: 03cc0c25-389f-4bf8-b48d-11878079f1ca
status: test
description: Detects a suspicious process spawning from an "mshta.exe" process, which could be indicative of a malicious HTA script execution
references:
    - https://web.archive.org/web/20150906062519/https://www.trustedsec.com/july-2015/malicious-htas/
author: Michael Haag
date: 2019-01-16
modified: 2023-02-06
tags:
    - attack.stealth
    - attack.t1218.005
    - car.2013-02-003
    - car.2013-03-001
    - car.2014-04-003
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\mshta.exe'
    selection_child:
        - Image|endswith:
              - '\cmd.exe'
              - '\powershell.exe'
              - '\pwsh.exe'
              - '\wscript.exe'
              - '\cscript.exe'
              - '\sh.exe'
              - '\bash.exe'
              - '\reg.exe'
              - '\regsvr32.exe'
              - '\bitsadmin.exe'
        - OriginalFileName:
              - 'Cmd.Exe'
              - 'PowerShell.EXE'
              - 'pwsh.dll'
              - 'wscript.exe'
              - 'cscript.exe'
              - 'Bash.exe'
              - 'reg.exe'
              - 'REGSVR32.EXE'
              - 'bitsadmin.exe'
    condition: all of selection*
falsepositives:
    - Printer software / driver installations
    - HP software
level: high
```
