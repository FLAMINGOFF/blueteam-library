---
title: Renamed Microsoft Teams Execution
summary: Detects the execution of a renamed Microsoft Teams binary.
sigma_id: 88f46b67-14d4-4f45-ac2c-d66984f22191
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques: []
author: Nasreddine Bencherchali (Nextron Systems)
date: '2024-07-12'
falsepositives:
  - Unknown
references:
  - Internal Research
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_renamed_msteams.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Renamed Microsoft Teams Execution
id: 88f46b67-14d4-4f45-ac2c-d66984f22191
status: test
description: Detects the execution of a renamed Microsoft Teams binary.
references:
    - Internal Research
author: Nasreddine Bencherchali (Nextron Systems)
date: 2024-07-12
tags:
    - attack.stealth
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        OriginalFileName:
            - 'msteams.exe'
            - 'teams.exe'
    filter_main_legit_names:
        Image|endswith:
            - '\msteams.exe'
            - '\teams.exe'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: medium
```
