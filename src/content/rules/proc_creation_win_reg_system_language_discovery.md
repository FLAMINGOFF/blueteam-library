---
title: System Language Discovery via Reg.Exe
summary: |-
  Detects the usage of Reg.Exe to query system language settings.
  Attackers may discover the system language to determine the geographic location of victims, customize payloads for specific regions,
  or avoid targeting certain locales to evade detection.
sigma_id: c43a5405-e8e1-4221-9ac9-dbe3fa14e886
status: experimental
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0007
techniques:
  - T1614.001
author: Marco Pedrinazzi (@pedrinazziM) (InTheCyber)
date: '2026-01-09'
falsepositives:
  - Unknown
references:
  - https://scythe.io/threat-thursday/threatthursday-darkside-ransomware
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_reg_system_language_discovery.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: System Language Discovery via Reg.Exe
id: c43a5405-e8e1-4221-9ac9-dbe3fa14e886
status: experimental
description: |
    Detects the usage of Reg.Exe to query system language settings.
    Attackers may discover the system language to determine the geographic location of victims, customize payloads for specific regions,
    or avoid targeting certain locales to evade detection.
references:
    - https://scythe.io/threat-thursday/threatthursday-darkside-ransomware
author: Marco Pedrinazzi (@pedrinazziM) (InTheCyber)
date: 2026-01-09
tags:
    - attack.discovery
    - attack.t1614.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\reg.exe'
        - OriginalFileName: 'reg.exe'
    selection_cli:
        CommandLine|contains|all:
            - 'query'
            - 'Control\Nls\Language'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_reg_system_language_discovery/info.yml
simulation:
    - type: atomic-red-team
      name: Discover System Language by Registry Query
      technique: T1614.001
      atomic_guid: 631d4cf1-42c9-4209-8fe9-6bd4de9421be
```
