---
title: MMC20 Lateral Movement
summary: Detects MMC20.Application Lateral Movement; specifically looks for the spawning of the parent MMC.exe with a command line of "-Embedding" as a child of svchost.exe
sigma_id: f1f3bf22-deb2-418d-8cce-e1a45e46a5bd
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
  - TA0008
techniques:
  - T1021.003
author: '@2xxeformyshirt (Security Risk Advisors) - rule; Teymur Kheirkhabarov (idea)'
date: '2020-03-04'
modified: '2021-11-27'
falsepositives:
  - Unlikely
references:
  - https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/
  - https://drive.google.com/file/d/1lKya3_mLnR3UQuCoiYruO3qgu052_iS_/view?usp=sharing
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_mmc_mmc20_lateral_movement.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: MMC20 Lateral Movement
id: f1f3bf22-deb2-418d-8cce-e1a45e46a5bd
status: test
description: Detects MMC20.Application Lateral Movement; specifically looks for the spawning of the parent MMC.exe with a command line of "-Embedding" as a child of svchost.exe
references:
    - https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/
    - https://drive.google.com/file/d/1lKya3_mLnR3UQuCoiYruO3qgu052_iS_/view?usp=sharing
author: '@2xxeformyshirt (Security Risk Advisors) - rule; Teymur Kheirkhabarov (idea)'
date: 2020-03-04
modified: 2021-11-27
tags:
    - attack.execution
    - attack.lateral-movement
    - attack.t1021.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\svchost.exe'
        Image|endswith: '\mmc.exe'
        CommandLine|contains: '-Embedding'
    condition: selection
falsepositives:
    - Unlikely
level: high
```
