---
title: Suspicious Powercfg Execution To Change Lock Screen Timeout
summary: Detects suspicious execution of 'Powercfg.exe' to change lock screen timeout
sigma_id: f8d6a15e-4bc8-4c27-8e5d-2b10f0b73e5b
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques: []
author: frack113
date: '2022-11-18'
falsepositives:
  - Unknown
references:
  - https://blogs.vmware.com/security/2022/11/batloader-the-evasive-downloader-malware.html
  - https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_powercfg_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Powercfg Execution To Change Lock Screen Timeout
id: f8d6a15e-4bc8-4c27-8e5d-2b10f0b73e5b
status: test
description: Detects suspicious execution of 'Powercfg.exe' to change lock screen timeout
references:
    - https://blogs.vmware.com/security/2022/11/batloader-the-evasive-downloader-malware.html
    - https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options
author: frack113
date: 2022-11-18
tags:
    - attack.stealth
logsource:
    category: process_creation
    product: windows
detection:
    selection_power:
        - Image|endswith: '\powercfg.exe'
        - OriginalFileName: 'PowerCfg.exe'
    selection_standby:
        # powercfg.exe /SETACVALUEINDEX SCHEME_CURRENT SUB_VIDEO VIDEOCONLOCK
        - CommandLine|contains|all:
              - '/setacvalueindex '
              - 'SCHEME_CURRENT'
              - 'SUB_VIDEO'
              - 'VIDEOCONLOCK'
        # powercfg -change -standby-timeout-dc 3000
        # powercfg -change -standby-timeout-ac 3000
        - CommandLine|contains|all:
              - '-change '
              - '-standby-timeout-'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```
