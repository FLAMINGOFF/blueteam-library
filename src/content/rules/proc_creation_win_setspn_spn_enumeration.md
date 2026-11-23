---
title: Potential SPN Enumeration Via Setspn.EXE
summary: Detects service principal name (SPN) enumeration used for Kerberoasting
sigma_id: 1eeed653-dbc8-4187-ad0c-eeebb20e6599
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0006
techniques:
  - T1558.003
author: Markus Neis, keepwatch
date: '2018-11-14'
modified: '2023-10-23'
falsepositives:
  - Administration activity
references:
  - https://web.archive.org/web/20200329173843/https://p16.praetorian.com/blog/how-to-use-kerberoasting-t1208-for-privilege-escalation
  - https://www.praetorian.com/blog/how-to-use-kerberoasting-t1208-for-privilege-escalation/?edition=2019
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_setspn_spn_enumeration.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential SPN Enumeration Via Setspn.EXE
id: 1eeed653-dbc8-4187-ad0c-eeebb20e6599
status: test
description: Detects service principal name (SPN) enumeration used for Kerberoasting
references:
    - https://web.archive.org/web/20200329173843/https://p16.praetorian.com/blog/how-to-use-kerberoasting-t1208-for-privilege-escalation
    - https://www.praetorian.com/blog/how-to-use-kerberoasting-t1208-for-privilege-escalation/?edition=2019
author: Markus Neis, keepwatch
date: 2018-11-14
modified: 2023-10-23
tags:
    - attack.credential-access
    - attack.t1558.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_pe:
        - Image|endswith: '\setspn.exe'
        - OriginalFileName: 'setspn.exe'
        - Description|contains|all:
              - 'Query or reset the computer'
              - 'SPN attribute'
    selection_cli:
        CommandLine|contains:
            - ' -q '
            - ' /q '
    condition: all of selection_*
falsepositives:
    - Administration activity
level: medium
```
