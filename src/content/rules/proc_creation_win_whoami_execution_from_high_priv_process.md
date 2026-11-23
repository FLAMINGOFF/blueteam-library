---
title: Whoami.EXE Execution From Privileged Process
summary: Detects the execution of "whoami.exe" by privileged accounts that are often abused by threat actors
sigma_id: 79ce34ca-af29-4d0e-b832-fc1b377020db
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
  - TA0007
techniques:
  - T1033
author: Florian Roth (Nextron Systems), Teymur Kheirkhabarov
date: '2022-01-28'
modified: '2023-12-04'
falsepositives:
  - Unknown
references:
  - https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment
  - https://web.archive.org/web/20221019044836/https://nsudo.m2team.org/en-us/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_whoami_execution_from_high_priv_process.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Whoami.EXE Execution From Privileged Process
id: 79ce34ca-af29-4d0e-b832-fc1b377020db
related:
    - id: 80167ada-7a12-41ed-b8e9-aa47195c66a1
      type: obsolete
status: test
description: Detects the execution of "whoami.exe" by privileged accounts that are often abused by threat actors
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment
    - https://web.archive.org/web/20221019044836/https://nsudo.m2team.org/en-us/
author: Florian Roth (Nextron Systems), Teymur Kheirkhabarov
date: 2022-01-28
modified: 2023-12-04
tags:
    - attack.privilege-escalation
    - attack.discovery
    - attack.t1033
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - OriginalFileName: 'whoami.exe'
        - Image|endswith: '\whoami.exe'
    selection_user:
        User|contains:
            - 'AUTHORI'
            - 'AUTORI'
            - 'TrustedInstaller'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
