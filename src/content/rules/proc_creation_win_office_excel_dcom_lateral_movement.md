---
title: Potential Excel.EXE DCOM Lateral Movement Via ActivateMicrosoftApp
summary: Detects suspicious child processes of Excel which could be an indicator of lateral movement leveraging the "ActivateMicrosoftApp" Excel DCOM object.
sigma_id: 551d9c1f-816c-445b-a7a6-7a3864720d60
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0008
techniques:
  - T1021.003
author: Aaron Stratton
date: '2023-11-13'
falsepositives:
  - Unknown
references:
  - https://posts.specterops.io/lateral-movement-abuse-the-power-of-dcom-excel-application-3c016d0d9922
  - https://github.com/grayhatkiller/SharpExShell
  - https://learn.microsoft.com/en-us/office/vba/api/excel.xlmsapplication
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_office_excel_dcom_lateral_movement.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential Excel.EXE DCOM Lateral Movement Via ActivateMicrosoftApp
id: 551d9c1f-816c-445b-a7a6-7a3864720d60
status: test
description: |
    Detects suspicious child processes of Excel which could be an indicator of lateral movement leveraging the "ActivateMicrosoftApp" Excel DCOM object.
references:
    - https://posts.specterops.io/lateral-movement-abuse-the-power-of-dcom-excel-application-3c016d0d9922
    - https://github.com/grayhatkiller/SharpExShell
    - https://learn.microsoft.com/en-us/office/vba/api/excel.xlmsapplication
author: Aaron Stratton
date: 2023-11-13
tags:
    - attack.t1021.003
    - attack.lateral-movement
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\excel.exe'
    selection_child:
        - OriginalFileName:
          - 'foxprow.exe'
          - 'schdplus.exe'
          - 'winproj.exe'
        - Image|endswith:
          - '\foxprow.exe'
          - '\schdplus.exe'
          - '\winproj.exe'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
