---
title: Potential Suspicious Activity Using SeCEdit
summary: Detects potential suspicious behaviour using secedit.exe. Such as exporting or modifying the security policy
sigma_id: c2c76b77-32be-4d1f-82c9-7e544bdfe0eb
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0009
  - TA0007
  - TA0003
  - TA0006
  - TA0004
  - TA0002
techniques:
  - T1685.001
  - T1547.001
  - T1505.005
  - T1556.002
  - T1685
  - T1574.007
  - T1564.002
  - T1546.008
  - T1546.007
  - T1547.014
  - T1547.010
  - T1547.002
  - T1557
  - T1082
author: Janantha Marasinghe
date: '2022-11-18'
modified: '2022-12-30'
falsepositives:
  - Legitimate administrative use
references:
  - https://blueteamops.medium.com/secedit-and-i-know-it-595056dee53d
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/secedit
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_secedit_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential Suspicious Activity Using SeCEdit
id: c2c76b77-32be-4d1f-82c9-7e544bdfe0eb
status: test
description: Detects potential suspicious behaviour using secedit.exe. Such as exporting or modifying the security policy
references:
    - https://blueteamops.medium.com/secedit-and-i-know-it-595056dee53d
    - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/secedit
author: Janantha Marasinghe
date: 2022-11-18
modified: 2022-12-30
tags:
    - attack.collection
    - attack.discovery
    - attack.persistence
    - attack.credential-access
    - attack.privilege-escalation
    - attack.execution
    - attack.stealth
    - attack.defense-impairment
    - attack.t1685.001
    - attack.t1547.001
    - attack.t1505.005
    - attack.t1556.002
    - attack.t1685
    - attack.t1574.007
    - attack.t1564.002
    - attack.t1546.008
    - attack.t1546.007
    - attack.t1547.014
    - attack.t1547.010
    - attack.t1547.002
    - attack.t1557
    - attack.t1082
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\secedit.exe'
        - OriginalFileName: 'SeCEdit'
    selection_flags_discovery:
        CommandLine|contains|all:
            - '/export'
            - '/cfg'
    selection_flags_configure:
        CommandLine|contains|all:
            - '/configure'
            - '/db'
    # filter:
    #     SubjectUserName|endswith: '$'  SubjectUserName is from event ID 4719 in the Windows Security log
    condition: selection_img and (1 of selection_flags_*)
falsepositives:
    - Legitimate administrative use
level: medium
```
