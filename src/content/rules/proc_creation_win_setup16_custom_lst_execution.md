---
title: Setup16.EXE Execution With Custom .Lst File
summary: |-
  Detects the execution of "Setup16.EXE" and old installation utility with a custom ".lst" file.
  These ".lst" file can contain references to external program that "Setup16.EXE" will execute.
  Attackers and adversaries might leverage this as a living of the land utility.
sigma_id: 99c8be4f-3087-4f9f-9c24-8c7e257b442e
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
  - TA0003
  - TA0002
  - TA0005
techniques:
  - T1574.005
author: frack113
date: '2024-12-01'
falsepositives:
  - On modern Windows system, the "Setup16" utility is practically never used, hence false positive should be very rare.
references:
  - https://www.hexacorn.com/blog/2024/10/12/the-sweet16-the-oldbin-lolbin-called-setup16-exe/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_setup16_custom_lst_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Setup16.EXE Execution With Custom .Lst File
id: 99c8be4f-3087-4f9f-9c24-8c7e257b442e
status: test
description: |
    Detects the execution of "Setup16.EXE" and old installation utility with a custom ".lst" file.
    These ".lst" file can contain references to external program that "Setup16.EXE" will execute.
    Attackers and adversaries might leverage this as a living of the land utility.
references:
    - https://www.hexacorn.com/blog/2024/10/12/the-sweet16-the-oldbin-lolbin-called-setup16-exe/
author: frack113
date: 2024-12-01
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.execution
    - attack.stealth
    - attack.t1574.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage: 'C:\Windows\SysWOW64\setup16.exe'
        ParentCommandLine|contains: ' -m '
    filter_optional_valid_path:
        Image|startswith: 'C:\~MSSETUP.T\'
    condition: selection and not 1 of filter_optional_*
falsepositives:
    - On modern Windows system, the "Setup16" utility is practically never used, hence false positive should be very rare.
level: medium
```
