---
title: Potential Configuration And Service Reconnaissance Via Reg.EXE
summary: >-
  Detects the usage of "reg.exe" in order to query reconnaissance information from the registry. Adversaries may interact with the Windows registry to gather information about credentials, the system,
  configuration, and installed software.
sigma_id: 970007b7-ce32-49d0-a4a4-fbef016950bd
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0007
techniques:
  - T1012
  - T1007
author: Timur Zinniatullin, oscd.community
date: '2019-10-21'
modified: '2026-10-19'
falsepositives:
  - Discord
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1012/T1012.md
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_reg_query_registry.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential Configuration And Service Reconnaissance Via Reg.EXE
id: 970007b7-ce32-49d0-a4a4-fbef016950bd
status: test
description: Detects the usage of "reg.exe" in order to query reconnaissance information from the registry. Adversaries may interact with the Windows registry to gather information about credentials, the system, configuration, and installed software.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1012/T1012.md
author: Timur Zinniatullin, oscd.community
date: 2019-10-21
modified: 2026-10-19
tags:
    - attack.discovery
    - attack.t1012
    - attack.t1007
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\reg.exe'
        - OriginalFileName: 'reg.exe'
    selection_flag:
        CommandLine|contains: ' query '
    selection_key:
        CommandLine|contains:
            - 'currentVersion\windows'
            - 'winlogon\'
            - 'currentVersion\shellServiceObjectDelayLoad'
            - 'currentVersion\run' # Also covers the strings "RunOnce", "RunOnceEx" and "runServicesOnce"
            - 'currentVersion\policies\explorer\run'
            - 'currentcontrolset\services'
    filter_optional_yammer:
        ParentImage|endswith: '\Yammer.exe'
        CommandLine: 'C:\Windows\system32\reg.exe QUERY HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Yammer'
    condition: all of selection_* and not 1 of filter_optional_*
falsepositives:
    - Discord
level: medium
```
