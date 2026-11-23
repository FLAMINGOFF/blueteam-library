---
title: Suspicious Scheduled Task Name As GUID
summary: Detects creation of a scheduled task with a GUID like name
sigma_id: ff2fff64-4cd6-4a2b-ba7d-e28a30bbe66b
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
  - TA0003
  - TA0002
techniques:
  - T1053.005
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-10-31'
falsepositives:
  - Legitimate software naming their tasks as GUIDs
references:
  - https://thedfirreport.com/2022/10/31/follina-exploit-leads-to-domain-compromise/
  - https://thedfirreport.com/2022/02/21/qbot-and-zerologon-lead-to-full-domain-compromise/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_schtasks_guid_task_name.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Scheduled Task Name As GUID
id: ff2fff64-4cd6-4a2b-ba7d-e28a30bbe66b
status: test
description: Detects creation of a scheduled task with a GUID like name
references:
    - https://thedfirreport.com/2022/10/31/follina-exploit-leads-to-domain-compromise/
    - https://thedfirreport.com/2022/02/21/qbot-and-zerologon-lead-to-full-domain-compromise/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-10-31
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.execution
    - attack.t1053.005
logsource:
    product: windows
    category: process_creation
detection:
    selection_img:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains: '/Create '
    selection_tn:
        CommandLine|contains:
            # Can start with single or double quote
            - '/TN "{'
            - "/TN '{"
            - "/TN {"
    selection_end:
        CommandLine|contains:
            # Ending of the name to avoid possible FP in the rest of the commandline
            - '}"'
            - "}'"
            - '} '
    condition: all of selection_*
falsepositives:
    - Legitimate software naming their tasks as GUIDs
level: medium
```
