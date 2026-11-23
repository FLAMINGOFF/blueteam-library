---
title: File Explorer Folder Opened Using Explorer Folder Shortcut Via Shell
summary: Detects the initial execution of "cmd.exe" which spawns "explorer.exe" with the appropriate command line arguments for opening the "My Computer" folder.
sigma_id: c3d76afc-93df-461e-8e67-9b2bad3f2ac4
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0007
techniques:
  - T1135
author: '@Kostastsale'
date: '2022-12-22'
modified: '2024-08-23'
falsepositives:
  - Unknown
references:
  - https://ss64.com/nt/shell.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_explorer_folder_shortcut_via_shell_binary.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: File Explorer Folder Opened Using Explorer Folder Shortcut Via Shell
id: c3d76afc-93df-461e-8e67-9b2bad3f2ac4
status: test
description: |
    Detects the initial execution of "cmd.exe" which spawns "explorer.exe" with the appropriate command line arguments for opening the "My Computer" folder.
author: '@Kostastsale'
references:
    - https://ss64.com/nt/shell.html
date: 2022-12-22
modified: 2024-08-23
tags:
    - attack.discovery
    - attack.t1135
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        ParentImage|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
        Image|endswith: '\explorer.exe'
        CommandLine|contains: 'shell:mycomputerfolder'
    condition: selection
falsepositives:
    - Unknown
level: high
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_explorer_folder_shortcut_via_shell_binary/info.yml
```
