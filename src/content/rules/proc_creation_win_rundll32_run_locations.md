---
title: Suspicious Process Start Locations
summary: Detects suspicious process run from unusual locations
sigma_id: 15b75071-74cc-47e0-b4c6-b43744a62a2b
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1036
author: juju4, Jonhnathan Ribeiro, oscd.community
date: '2019-01-16'
modified: '2022-01-07'
falsepositives:
  - False positives depend on scripts and administrative tools used in the monitored environment
references:
  - https://car.mitre.org/wiki/CAR-2013-05-002
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_rundll32_run_locations.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Process Start Locations
id: 15b75071-74cc-47e0-b4c6-b43744a62a2b
status: test
description: Detects suspicious process run from unusual locations
references:
    - https://car.mitre.org/wiki/CAR-2013-05-002
author: juju4, Jonhnathan Ribeiro, oscd.community
date: 2019-01-16
modified: 2022-01-07
tags:
    - attack.stealth
    - attack.t1036
    - car.2013-05-002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|contains:
              - ':\RECYCLER\'
              - ':\SystemVolumeInformation\'
        - Image|startswith:
              - 'C:\Windows\Tasks\'
              - 'C:\Windows\debug\'
              - 'C:\Windows\fonts\'
              - 'C:\Windows\help\'
              - 'C:\Windows\drivers\'
              - 'C:\Windows\addins\'
              - 'C:\Windows\cursors\'
              - 'C:\Windows\system32\tasks\'
    condition: selection
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: medium
```
