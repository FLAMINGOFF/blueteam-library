---
title: Application Removed Via Wmic.EXE
summary: Detects the removal or uninstallation of an application via "Wmic.EXE".
sigma_id: b53317a0-8acf-4fd1-8de8-a5401e776b96
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1047
author: frack113
date: '2022-01-28'
modified: '2024-07-02'
falsepositives:
  - Unknown
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1047/T1047.md#atomic-test-10---application-uninstall-using-wmic
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_wmic_uninstall_application.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Application Removed Via Wmic.EXE
id: b53317a0-8acf-4fd1-8de8-a5401e776b96
related:
    - id: 847d5ff3-8a31-4737-a970-aeae8fe21765 # Uninstall Security Products
      type: derived
status: test
description: Detects the removal or uninstallation of an application via "Wmic.EXE".
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1047/T1047.md#atomic-test-10---application-uninstall-using-wmic
author: frack113
date: 2022-01-28
modified: 2024-07-02
tags:
    - attack.execution
    - attack.t1047
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\WMIC.exe'
        - OriginalFileName: 'wmic.exe'
    selection_cli:
        CommandLine|contains|all:
            - 'call'
            - 'uninstall'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
simulation:
    - type: atomic-red-team
      name: Application uninstall using WMIC
      technique: T1047
      atomic_guid: c510d25b-1667-467d-8331-a56d3e9bc4ff
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_wmic_uninstall_application/info.yml
```
