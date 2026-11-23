---
title: Psexec Execution
summary: Detects user accept agreement execution in psexec commandline
sigma_id: 730fc21b-eaff-474b-ad23-90fd265d4988
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
  - TA0008
techniques:
  - T1569
  - T1021
author: omkar72
date: '2020-10-30'
modified: '2023-02-28'
falsepositives:
  - Administrative scripts.
references:
  - https://www.fireeye.com/blog/threat-research/2020/10/kegtap-and-singlemalt-with-a-ransomware-chaser.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_sysinternals_psexec_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Psexec Execution
id: 730fc21b-eaff-474b-ad23-90fd265d4988
status: test
description: Detects user accept agreement execution in psexec commandline
references:
    - https://www.fireeye.com/blog/threat-research/2020/10/kegtap-and-singlemalt-with-a-ransomware-chaser.html
author: omkar72
date: 2020-10-30
modified: 2023-02-28
tags:
    - attack.execution
    - attack.lateral-movement
    - attack.t1569
    - attack.t1021
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\psexec.exe'
        - OriginalFileName: 'psexec.c'
    condition: selection
falsepositives:
    - Administrative scripts.
level: medium
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_sysinternals_psexec_execution/info.yml
```
