---
title: Harvesting Of Wifi Credentials Via Netsh.EXE
summary: Detect the harvesting of wifi credentials using netsh.exe
sigma_id: 42b1a5b8-353f-4f10-b256-39de4467faff
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0007
  - TA0006
techniques:
  - T1040
author: Andreas Hunkeler (@Karneades), oscd.community
date: '2020-04-20'
modified: '2023-02-13'
falsepositives:
  - Unknown
references:
  - https://blog.malwarebytes.com/threat-analysis/2020/04/new-agenttesla-variant-steals-wifi-credentials/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_netsh_wifi_credential_harvesting.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Harvesting Of Wifi Credentials Via Netsh.EXE
id: 42b1a5b8-353f-4f10-b256-39de4467faff
status: test
description: Detect the harvesting of wifi credentials using netsh.exe
references:
    - https://blog.malwarebytes.com/threat-analysis/2020/04/new-agenttesla-variant-steals-wifi-credentials/
author: Andreas Hunkeler (@Karneades), oscd.community
date: 2020-04-20
modified: 2023-02-13
tags:
    - attack.discovery
    - attack.credential-access
    - attack.t1040
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\netsh.exe'
        - OriginalFileName: 'netsh.exe'
    selection_cli:
        CommandLine|contains|all:
            - 'wlan'
            - ' s'
            - ' p'
            - ' k'
            - '=clear'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```
