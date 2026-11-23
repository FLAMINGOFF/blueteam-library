---
title: Windows Hotfix Updates Reconnaissance Via Wmic.EXE
summary: Detects the execution of wmic with the "qfe" flag in order to obtain information about installed hotfix updates on the system. This is often used by pentester and attacker enumeration scripts
sigma_id: dfd2fcb7-8bd5-4daa-b132-5adb61d6ad45
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1047
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-06-20'
modified: '2023-02-14'
falsepositives:
  - Unknown
references:
  - https://github.com/carlospolop/PEASS-ng/blob/fa0f2e17fbc1d86f1fd66338a40e665e7182501d/winPEAS/winPEASbat/winPEAS.bat
  - https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_wmic_recon_hotfix.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Windows Hotfix Updates Reconnaissance Via Wmic.EXE
id: dfd2fcb7-8bd5-4daa-b132-5adb61d6ad45
status: test
description: Detects the execution of wmic with the "qfe" flag in order to obtain information about installed hotfix updates on the system. This is often used by pentester and attacker enumeration scripts
references:
    - https://github.com/carlospolop/PEASS-ng/blob/fa0f2e17fbc1d86f1fd66338a40e665e7182501d/winPEAS/winPEASbat/winPEAS.bat
    - https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-06-20
modified: 2023-02-14
tags:
    - attack.execution
    - attack.t1047
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - OriginalFileName: 'wmic.exe'
        - Image|endswith: '\WMIC.exe'
    selection_cli:
        CommandLine|contains: ' qfe'
    condition: all of selection*
falsepositives:
    - Unknown
level: medium
simulation:
    - type: atomic-red-team
      name: WMI Reconnaissance Software
      technique: T1047
      atomic_guid: 718aebaa-d0e0-471a-8241-c5afa69c7414
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_wmic_recon_hotfix/info.yml
```
