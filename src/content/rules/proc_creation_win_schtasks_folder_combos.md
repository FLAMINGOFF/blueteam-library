---
title: Schtasks From Suspicious Folders
summary: Detects scheduled task creations that have suspicious action command and folder combinations
sigma_id: 8a8379b8-780b-4dbf-b1e9-31c8d112fefb
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
  - TA0003
  - TA0002
techniques:
  - T1053.005
author: Florian Roth (Nextron Systems)
date: '2022-04-15'
modified: '2022-11-18'
falsepositives:
  - Unknown
references:
  - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/lazarus-dream-job-chemical
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_schtasks_folder_combos.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Schtasks From Suspicious Folders
id: 8a8379b8-780b-4dbf-b1e9-31c8d112fefb
status: test
description: Detects scheduled task creations that have suspicious action command and folder combinations
references:
    - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/lazarus-dream-job-chemical
author: Florian Roth (Nextron Systems)
date: 2022-04-15
modified: 2022-11-18
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.execution
    - attack.t1053.005
logsource:
    product: windows
    category: process_creation
detection:
    selection_img:
        - Image|endswith: '\schtasks.exe'
        - OriginalFileName: 'schtasks.exe'
    selection_create:
        CommandLine|contains: ' /create '
    selection_command:
        CommandLine|contains:
            - 'powershell'
            - 'pwsh'
            - 'cmd /c '
            - 'cmd /k '
            - 'cmd /r '
            - 'cmd.exe /c '
            - 'cmd.exe /k '
            - 'cmd.exe /r '
    selection_all_folders:
        CommandLine|contains:
            - 'C:\ProgramData\'
            - '%ProgramData%'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
