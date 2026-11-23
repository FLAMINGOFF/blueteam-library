---
title: Always Install Elevated MSI Spawned Cmd And Powershell
summary: Detects Windows Installer service (msiexec.exe) spawning "cmd" or "powershell"
sigma_id: 1e53dd56-8d83-4eb4-a43e-b790a05510aa
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
techniques:
  - T1548.002
author: Teymur Kheirkhabarov (idea), Mangatas Tondang (rule), oscd.community
date: '2020-10-13'
modified: '2022-10-20'
falsepositives:
  - Unknown
references:
  - https://image.slidesharecdn.com/kheirkhabarovoffzonefinal-181117201458/95/hunting-for-privilege-escalation-in-windows-environment-50-638.jpg
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_susp_elavated_msi_spawned_shell.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Always Install Elevated MSI Spawned Cmd And Powershell
id: 1e53dd56-8d83-4eb4-a43e-b790a05510aa
status: test
description: Detects Windows Installer service (msiexec.exe) spawning "cmd" or "powershell"
references:
    - https://image.slidesharecdn.com/kheirkhabarovoffzonefinal-181117201458/95/hunting-for-privilege-escalation-in-windows-environment-50-638.jpg
author: Teymur Kheirkhabarov (idea), Mangatas Tondang (rule), oscd.community
date: 2020-10-13
modified: 2022-10-20
tags:
    - attack.privilege-escalation
    - attack.t1548.002
logsource:
    product: windows
    category: process_creation
detection:
    selection_img:
        - Image|endswith:
              - '\cmd.exe'
              - '\powershell.exe'
              - '\pwsh.exe'
        - OriginalFileName:
              - 'Cmd.Exe'
              - 'PowerShell.EXE'
              - 'pwsh.dll'
    selection_parent:
        ParentImage|contains|all:
            - '\Windows\Installer\'
            - 'msi'
        ParentImage|endswith: 'tmp'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```
