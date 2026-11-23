---
title: Rundll32 Execution Without Parameters
summary: Detects rundll32 execution without parameters as observed when running Metasploit windows/smb/psexec exploit module
sigma_id: 5bb68627-3198-40ca-b458-49f973db8752
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0008
  - TA0002
techniques:
  - T1021.002
  - T1570
  - T1569.002
author: Bartlomiej Czyz, Relativity
date: '2021-01-31'
modified: '2023-02-28'
falsepositives:
  - False positives may occur if a user called rundll32 from CLI with no options
references:
  - https://bczyz1.github.io/2021/01/30/psexec.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_rundll32_without_parameters.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Rundll32 Execution Without Parameters
id: 5bb68627-3198-40ca-b458-49f973db8752
status: test
description: Detects rundll32 execution without parameters as observed when running Metasploit windows/smb/psexec exploit module
references:
    - https://bczyz1.github.io/2021/01/30/psexec.html
author: Bartlomiej Czyz, Relativity
date: 2021-01-31
modified: 2023-02-28
tags:
    - attack.lateral-movement
    - attack.t1021.002
    - attack.t1570
    - attack.execution
    - attack.t1569.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - 'rundll32.exe'
            - 'rundll32'
    condition: selection
falsepositives:
    - False positives may occur if a user called rundll32 from CLI with no options
level: high
```
