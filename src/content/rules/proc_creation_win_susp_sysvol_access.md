---
title: Suspicious SYSVOL Domain Group Policy Access
summary: Detects Access to Domain Group Policies stored in SYSVOL
sigma_id: 05f3c945-dcc8-4393-9f3d-af65077a8f86
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0006
techniques:
  - T1552.006
author: Markus Neis, Jonhnathan Ribeiro, oscd.community
date: '2018-04-09'
modified: '2022-01-07'
falsepositives:
  - Administrative activity
references:
  - https://adsecurity.org/?p=2288
  - https://www.hybrid-analysis.com/sample/f2943f5e45befa52fb12748ca7171d30096e1d4fc3c365561497c618341299d5?environmentId=100
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_susp_sysvol_access.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious SYSVOL Domain Group Policy Access
id: 05f3c945-dcc8-4393-9f3d-af65077a8f86
status: test
description: Detects Access to Domain Group Policies stored in SYSVOL
references:
    - https://adsecurity.org/?p=2288
    - https://www.hybrid-analysis.com/sample/f2943f5e45befa52fb12748ca7171d30096e1d4fc3c365561497c618341299d5?environmentId=100
author: Markus Neis, Jonhnathan Ribeiro, oscd.community
date: 2018-04-09
modified: 2022-01-07
tags:
    - attack.credential-access
    - attack.t1552.006
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - '\SYSVOL\'
            - '\policies\'
    condition: selection
falsepositives:
    - Administrative activity
level: medium
```
