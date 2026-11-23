---
title: Suspicious Scheduled Task Creation Involving Temp Folder
summary: Detects the creation of scheduled tasks that involves a temporary folder and runs only once
sigma_id: 39019a4e-317f-4ce3-ae63-309a8c6b53c5
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
  - TA0002
  - TA0003
techniques:
  - T1053.005
author: Florian Roth (Nextron Systems)
date: '2021-03-11'
modified: '2022-10-09'
falsepositives:
  - Administrative activity
  - Software installation
references:
  - https://discuss.elastic.co/t/detection-and-response-for-hafnium-activity/266289/3
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_schtasks_creation_temp_folder.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Scheduled Task Creation Involving Temp Folder
id: 39019a4e-317f-4ce3-ae63-309a8c6b53c5
status: test
description: Detects the creation of scheduled tasks that involves a temporary folder and runs only once
references:
    - https://discuss.elastic.co/t/detection-and-response-for-hafnium-activity/266289/3
author: Florian Roth (Nextron Systems)
date: 2021-03-11
modified: 2022-10-09
tags:
    - attack.privilege-escalation
    - attack.execution
    - attack.persistence
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains|all:
            - ' /create '
            - ' /sc once '
            - '\Temp\'
    condition: selection
falsepositives:
    - Administrative activity
    - Software installation
level: high
```
