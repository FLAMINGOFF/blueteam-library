---
title: HackTool - WSASS Execution
summary: |-
  Detects execution of WSASS, a tool used to dump LSASS memory on Windows systems by leveraging WER's
  (Windows Error Reporting) WerFaultSecure.EXE to bypass PPL (Protected Process Light) protections.
sigma_id: 589ac73f-8e12-409c-964e-31a2f5775ae2
status: experimental
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0006
techniques:
  - T1003.001
author: Swachchhanda Shrawan Poudel (Nextron Systems)
date: '2025-11-23'
modified: '2026-01-09'
falsepositives:
  - Unlikely
references:
  - https://github.com/TwoSevenOneT/WSASS
  - https://www.zerosalarium.com/2025/09/Dumping-LSASS-With-WER-On-Modern-Windows-11.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_hktl_wsass.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: HackTool - WSASS Execution
id: 589ac73f-8e12-409c-964e-31a2f5775ae2
status: experimental
description: |
    Detects execution of WSASS, a tool used to dump LSASS memory on Windows systems by leveraging WER's
    (Windows Error Reporting) WerFaultSecure.EXE to bypass PPL (Protected Process Light) protections.
references:
    - https://github.com/TwoSevenOneT/WSASS
    - https://www.zerosalarium.com/2025/09/Dumping-LSASS-With-WER-On-Modern-Windows-11.html
author: Swachchhanda Shrawan Poudel (Nextron Systems)
date: 2025-11-23
modified: 2026-01-09
tags:
    - attack.credential-access
    - attack.t1003.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith: '\wsass.exe'
    selection_hash:
        Hashes|contains: 'IMPHASH=32F5095C9BBDCACF28FD4060EB4DFC42'
    selection_cli:
        # change to |re|i after Sigma v2.0 release
        # plain string without quotation marks as it has to match for both ' and "
        CommandLine|re: (?i)\.exe[\"\']?\s+[^\"]{0,64}werfaultsecure\.exe[\"\']?\s+\d{2,10} # wsass.exe "path to werfaultsecure" lsass_pid
    condition: 1 of selection_*
falsepositives:
    - Unlikely
level: high
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_hktl_wsass/info.yml
```
