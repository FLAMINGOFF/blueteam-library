---
title: Visual Basic Command Line Compiler Usage
summary: Detects successful code compilation via Visual Basic Command Line Compiler that utilizes Windows Resource to Object Converter.
sigma_id: 7b10f171-7f04-47c7-9fa2-5be43c76e535
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1027.004
author: Ensar Şamil, @sblmsrsn, @oscd_initiative
date: '2020-10-07'
modified: '2021-11-27'
falsepositives:
  - Utilization of this tool should not be seen in enterprise environment
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Vbc/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_lolbin_visual_basic_compiler.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Visual Basic Command Line Compiler Usage
id: 7b10f171-7f04-47c7-9fa2-5be43c76e535
status: test
description: Detects successful code compilation via Visual Basic Command Line Compiler that utilizes Windows Resource to Object Converter.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Vbc/
author: 'Ensar Şamil, @sblmsrsn, @oscd_initiative'
date: 2020-10-07
modified: 2021-11-27
tags:
    - attack.stealth
    - attack.t1027.004
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\vbc.exe'
        Image|endswith: '\cvtres.exe'
    condition: selection
falsepositives:
    - Utilization of this tool should not be seen in enterprise environment
level: high
```
