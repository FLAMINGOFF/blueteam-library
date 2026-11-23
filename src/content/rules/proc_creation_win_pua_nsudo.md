---
title: PUA - NSudo Execution
summary: Detects the use of NSudo tool for command execution
sigma_id: 771d1eb5-9587-4568-95fb-9ec44153a012
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1569.002
author: Florian Roth (Nextron Systems), Nasreddine Bencherchali
date: '2022-01-24'
modified: '2023-02-13'
falsepositives:
  - Legitimate use by administrators
references:
  - https://web.archive.org/web/20221019044836/https://nsudo.m2team.org/en-us/
  - https://www.winhelponline.com/blog/run-program-as-system-localsystem-account-windows/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_pua_nsudo.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: PUA - NSudo Execution
id: 771d1eb5-9587-4568-95fb-9ec44153a012
status: test
description: Detects the use of NSudo tool for command execution
references:
    - https://web.archive.org/web/20221019044836/https://nsudo.m2team.org/en-us/
    - https://www.winhelponline.com/blog/run-program-as-system-localsystem-account-windows/
author: Florian Roth (Nextron Systems), Nasreddine Bencherchali
date: 2022-01-24
modified: 2023-02-13
tags:
    - attack.execution
    - attack.t1569.002
    - attack.s0029
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith:
              - '\NSudo.exe'
              - '\NSudoLC.exe'
              - '\NSudoLG.exe'
        - OriginalFileName:
              - 'NSudo.exe'
              - 'NSudoLC.exe'
              - 'NSudoLG.exe'
    selection_cli:
        CommandLine|contains:
            # Covers Single/Double dash "-"/"--" + ":"
            - '-U:S ' # System
            - '-U:T ' # Trusted Installer
            - '-U:E ' # Elevated
            - '-P:E ' # Enable All Privileges
            - '-M:S ' # System Integrity
            - '-M:H ' # High Integrity
            # Covers Single/Double dash "-"/"--" + "="
            - '-U=S '
            - '-U=T '
            - '-U=E '
            - '-P=E '
            - '-M=S '
            - '-M=H '
            - '-ShowWindowMode:Hide'
    condition: all of selection_*
falsepositives:
    - Legitimate use by administrators
level: high
```
