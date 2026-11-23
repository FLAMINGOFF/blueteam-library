---
title: Suspicious Serv-U Process Pattern
summary: Detects a suspicious process pattern which could be a sign of an exploited Serv-U service
sigma_id: 58f4ea09-0fc2-4520-ba18-b85c540b0eaf
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0006
techniques:
  - T1555
author: Florian Roth (Nextron Systems)
date: '2021-07-14'
modified: '2022-07-14'
falsepositives:
  - Legitimate uses in which users or programs use the SSH service of Serv-U for remote command execution
references:
  - https://www.microsoft.com/security/blog/2021/07/13/microsoft-discovers-threat-actor-targeting-solarwinds-serv-u-software-with-0-day-exploit/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_servu_susp_child_process.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Serv-U Process Pattern
id: 58f4ea09-0fc2-4520-ba18-b85c540b0eaf
status: test
description: Detects a suspicious process pattern which could be a sign of an exploited Serv-U service
references:
    - https://www.microsoft.com/security/blog/2021/07/13/microsoft-discovers-threat-actor-targeting-solarwinds-serv-u-software-with-0-day-exploit/
author: Florian Roth (Nextron Systems)
date: 2021-07-14
modified: 2022-07-14
tags:
    - attack.credential-access
    - attack.t1555
    - cve.2021-35211
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\Serv-U.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\wscript.exe'
            - '\cscript.exe'
            - '\sh.exe'
            - '\bash.exe'
            - '\schtasks.exe'
            - '\regsvr32.exe'
            - '\wmic.exe'  # https://app.any.run/tasks/c903e9c8-0350-440c-8688-3881b556b8e0/
            - '\mshta.exe'
            - '\rundll32.exe'
            - '\msiexec.exe'
            - '\forfiles.exe'
            - '\scriptrunner.exe'
    condition: selection
falsepositives:
    - Legitimate uses in which users or programs use the SSH service of Serv-U for remote command execution
level: high
```
