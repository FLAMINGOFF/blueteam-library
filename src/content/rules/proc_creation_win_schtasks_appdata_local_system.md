---
title: Suspicious Schtasks Execution AppData Folder
summary: Detects the creation of a schtask that executes a file from C:\Users\<USER>\AppData\Local
sigma_id: c5c00f49-b3f9-45a6-997e-cfdecc6e1967
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
  - TA0002
  - TA0003
techniques:
  - T1053.005
  - T1059.001
author: pH-T (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: '2022-03-15'
modified: '2022-07-28'
falsepositives:
  - Unknown
references:
  - https://thedfirreport.com/2022/02/21/qbot-and-zerologon-lead-to-full-domain-compromise/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_schtasks_appdata_local_system.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Schtasks Execution AppData Folder
id: c5c00f49-b3f9-45a6-997e-cfdecc6e1967
status: test
description: 'Detects the creation of a schtask that executes a file from C:\Users\<USER>\AppData\Local'
references:
    - https://thedfirreport.com/2022/02/21/qbot-and-zerologon-lead-to-full-domain-compromise/
author: pH-T (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: 2022-03-15
modified: 2022-07-28
tags:
    - attack.privilege-escalation
    - attack.execution
    - attack.persistence
    - attack.t1053.005
    - attack.t1059.001
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains|all:
            - '/Create'
            - '/RU'
            - '/TR'
            - 'C:\Users\'
            - '\AppData\Local\'
        CommandLine|contains:
            - 'NT AUT' # This covers the usual NT AUTHORITY\SYSTEM
            - ' SYSTEM ' # SYSTEM is a valid value for schtasks hence it gets it's own value with space
    filter:
        # FP from test set in SIGMA
        ParentImage|contains|all:
            - '\AppData\Local\Temp\'
            - 'TeamViewer_.exe'
        Image|endswith: '\schtasks.exe'
        CommandLine|contains: '/TN TVInstallRestore'
    condition: selection and not filter
falsepositives:
    - Unknown
level: high
```
