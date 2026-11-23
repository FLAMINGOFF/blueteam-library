---
title: Sdclt Child Processes
summary: A General detection for sdclt spawning new processes. This could be an indicator of sdclt being used for bypass UAC techniques.
sigma_id: da2738f2-fadb-4394-afa7-0a0674885afa
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
techniques:
  - T1548.002
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
date: '2020-05-02'
modified: '2021-11-27'
falsepositives:
  - Unknown
references:
  - https://github.com/OTRF/detection-hackathon-apt29/issues/6
  - https://github.com/OTRF/ThreatHunter-Playbook/blob/2d4257f630f4c9770f78d0c1df059f891ffc3fec/docs/evals/apt29/detections/3.B.2_C36B49B5-DF58-4A34-9FE9-56189B9DEFEA.md
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_sdclt_child_process.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Sdclt Child Processes
id: da2738f2-fadb-4394-afa7-0a0674885afa
status: test
description: A General detection for sdclt spawning new processes. This could be an indicator of sdclt being used for bypass UAC techniques.
references:
    - https://github.com/OTRF/detection-hackathon-apt29/issues/6
    - https://github.com/OTRF/ThreatHunter-Playbook/blob/2d4257f630f4c9770f78d0c1df059f891ffc3fec/docs/evals/apt29/detections/3.B.2_C36B49B5-DF58-4A34-9FE9-56189B9DEFEA.md
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
date: 2020-05-02
modified: 2021-11-27
tags:
    - attack.privilege-escalation
    - attack.t1548.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\sdclt.exe'
    condition: selection
falsepositives:
    - Unknown
level: medium
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_sdclt_child_process/info.yml
```
