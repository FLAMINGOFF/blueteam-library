---
title: Renamed CreateDump Utility Execution
summary: Detects uses of a renamed legitimate createdump.exe LOLOBIN utility to dump process memory
sigma_id: 1a1ed54a-2ba4-4221-94d5-01dee560d71e
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
  - TA0006
techniques:
  - T1036
  - T1003.001
author: Florian Roth (Nextron Systems)
date: '2022-09-20'
modified: '2023-02-14'
falsepositives:
  - Command lines that use the same flags
references:
  - https://www.crowdstrike.com/blog/overwatch-exposes-aquatic-panda-in-possession-of-log-4-shell-exploit-tools/
  - https://twitter.com/bopin2020/status/1366400799199272960
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_renamed_createdump.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Renamed CreateDump Utility Execution
id: 1a1ed54a-2ba4-4221-94d5-01dee560d71e
related:
    - id: 515c8be5-e5df-4c5e-8f6d-a4a2f05e4b48
      type: similar
status: test
description: Detects uses of a renamed legitimate createdump.exe LOLOBIN utility to dump process memory
references:
    - https://www.crowdstrike.com/blog/overwatch-exposes-aquatic-panda-in-possession-of-log-4-shell-exploit-tools/
    - https://twitter.com/bopin2020/status/1366400799199272960
author: Florian Roth (Nextron Systems)
date: 2022-09-20
modified: 2023-02-14
tags:
    - attack.stealth
    - attack.t1036
    - attack.t1003.001
    - attack.credential-access
logsource:
    category: process_creation
    product: windows
detection:
    selection_pe:
        OriginalFileName: 'FX_VER_INTERNALNAME_STR'
    selection_cli:
        - CommandLine|contains|all:
              - ' -u ' # Short version of '--full'
              - ' -f ' # Short version of '--name'
              - '.dmp'
        - CommandLine|contains|all:
              - ' --full ' # Short version of '--full'
              - ' --name ' # Short version of '--name'
              - '.dmp'
    filter:
        Image|endswith: '\createdump.exe'
    condition: 1 of selection_* and not filter
falsepositives:
    - Command lines that use the same flags
level: high
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_renamed_createdump/info.yml
```
