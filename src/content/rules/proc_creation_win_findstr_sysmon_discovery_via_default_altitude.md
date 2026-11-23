---
title: Sysmon Discovery Via Default Driver Altitude Using Findstr.EXE
summary: >-
  Detects usage of "findstr" with the argument "385201". Which could indicate potential discovery of an installed Sysinternals Sysmon service using the default driver altitude (even if the name is
  changed).
sigma_id: 37db85d1-b089-490a-a59a-c7b6f984f480
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0007
techniques:
  - T1518.001
author: frack113
date: '2021-12-16'
modified: '2023-11-14'
falsepositives:
  - Unknown
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1518.001/T1518.001.md#atomic-test-5---security-software-discovery---sysmon-service
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_findstr_sysmon_discovery_via_default_altitude.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Sysmon Discovery Via Default Driver Altitude Using Findstr.EXE
id: 37db85d1-b089-490a-a59a-c7b6f984f480
status: test
description: Detects usage of "findstr" with the argument "385201". Which could indicate potential discovery of an installed Sysinternals Sysmon service using the default driver altitude (even if the name is changed).
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1518.001/T1518.001.md#atomic-test-5---security-software-discovery---sysmon-service
author: frack113
date: 2021-12-16
modified: 2023-11-14
tags:
    - attack.discovery
    - attack.t1518.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith:
              - '\find.exe'
              - '\findstr.exe'
        - OriginalFileName:
              - 'FIND.EXE'
              - 'FINDSTR.EXE'
    selection_cli:
        CommandLine|contains: ' 385201' # Sysmon driver default altitude
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_findstr_sysmon_discovery_via_default_altitude/info.yml
```
