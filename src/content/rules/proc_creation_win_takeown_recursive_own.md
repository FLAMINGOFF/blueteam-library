---
title: Suspicious Recursive Takeown
summary: Adversaries can interact with the DACLs using built-in Windows commands takeown which can grant adversaries higher permissions on specific files and folders
sigma_id: 554601fb-9b71-4bcc-abf4-21a611be4fde
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1222.001
author: frack113
date: '2022-01-30'
modified: '2022-11-21'
falsepositives:
  - Scripts created by developers and admins
  - Administrative activity
references:
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/takeown
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1222.001/T1222.001.md#atomic-test-1---take-ownership-using-takeown-utility
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_takeown_recursive_own.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Recursive Takeown
id: 554601fb-9b71-4bcc-abf4-21a611be4fde
status: test
description: Adversaries can interact with the DACLs using built-in Windows commands takeown which can grant adversaries higher permissions on specific files and folders
references:
    - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/takeown
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1222.001/T1222.001.md#atomic-test-1---take-ownership-using-takeown-utility
author: frack113
date: 2022-01-30
modified: 2022-11-21
tags:
    - attack.defense-impairment
    - attack.t1222.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\takeown.exe'
        CommandLine|contains|all:
            - '/f '
            - '/r'
    condition: selection
falsepositives:
    - Scripts created by developers and admins
    - Administrative activity
level: medium
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_takeown_recursive_own/info.yml
```
