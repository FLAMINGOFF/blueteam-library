---
title: System Restore Registry Modification via CommandLine
summary: Detects system restore registry modification via command line, which can be used by adversaries to disable system restore on the computer.
sigma_id: 7c06ab9b-b1d2-4ba9-b06e-09491ded20d9
status: experimental
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0040
techniques:
  - T1490
author: Swachchhanda Shrawan Poudel (Nextron Systems)
date: '2026-03-11'
falsepositives:
  - Unknown
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1490/T1490.md#atomic-test-9---disable-system-restore-through-registry
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_reg_system_restore_modification.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: System Restore Registry Modification via CommandLine
id: 7c06ab9b-b1d2-4ba9-b06e-09491ded20d9
related:
    - id: 5de03871-5d46-4539-a82d-3aa992a69a83
      type: similar
status: experimental
description: |
    Detects system restore registry modification via command line, which can be used by adversaries to disable system restore on the computer.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1490/T1490.md#atomic-test-9---disable-system-restore-through-registry
author: Swachchhanda Shrawan Poudel (Nextron Systems)
date: 2026-03-11
tags:
    - attack.impact
    - attack.t1490
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith:
              - '\powershell.exe'
              - '\pwsh.exe'
              - '\reg.exe'
        - OriginalFileName:
              - 'powershell.exe'
              - 'pwsh.dll'
              - 'reg.exe'
    selection_cli_action:
        CommandLine|contains:
            - ' add '
            - 'Set-ItemProperty'
            - 'New-ItemProperty'
    selection_cli_reg_root:
        CommandLine|contains:
            - '\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore'
            - '\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
    selection_cli_reg_key:
        CommandLine|contains:
            - 'DisableConfig'
            - 'DisableSR'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_reg_system_restore_modification/info.yml
simulation:
    - type: atomic-red-team
      name: Disable System Restore Through Registry
      technique: T1490
      atomic_guid: 66e647d1-8741-4e43-b7c1-334760c2047f
```
