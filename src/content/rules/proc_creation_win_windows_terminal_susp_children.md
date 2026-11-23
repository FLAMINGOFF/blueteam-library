---
title: Suspicious WindowsTerminal Child Processes
summary: Detects suspicious children spawned via the Windows Terminal application which could be a sign of persistence via WindowsTerminal (see references section)
sigma_id: 8de89e52-f6e1-4b5b-afd1-41ecfa300d48
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
  - TA0003
techniques: []
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-07-25'
modified: '2023-02-14'
falsepositives:
  - Other legitimate "Windows Terminal" profiles
references:
  - https://persistence-info.github.io/Data/windowsterminalprofile.html
  - https://twitter.com/nas_bench/status/1550836225652686848
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_windows_terminal_susp_children.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious WindowsTerminal Child Processes
id: 8de89e52-f6e1-4b5b-afd1-41ecfa300d48
status: test
description: Detects suspicious children spawned via the Windows Terminal application which could be a sign of persistence via WindowsTerminal (see references section)
references:
    - https://persistence-info.github.io/Data/windowsterminalprofile.html
    - https://twitter.com/nas_bench/status/1550836225652686848
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-07-25
modified: 2023-02-14
tags:
    - attack.execution
    - attack.persistence
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\WindowsTerminal.exe'
            - '\wt.exe'
    selection_susp:
        - Image|endswith:
              # Add more LOLBINS
              - '\rundll32.exe'
              - '\regsvr32.exe'
              - '\certutil.exe'
              - '\cscript.exe'
              - '\wscript.exe'
              - '\csc.exe'
        - Image|contains:
              # Add more suspicious paths
              - 'C:\Users\Public\'
              - '\Downloads\'
              - '\Desktop\'
              - '\AppData\Local\Temp\'
              - '\Windows\TEMP\'
        - CommandLine|contains:
              # Add more suspicious commandline
              - ' iex '
              - ' icm'
              - 'Invoke-'
              - 'Import-Module '
              - 'ipmo '
              - 'DownloadString('
              - ' /c '
              - ' /k '
              - ' /r '
    filter_builtin_visual_studio_shell:
        CommandLine|contains|all:
            - 'Import-Module'
            - 'Microsoft.VisualStudio.DevShell.dll'
            - 'Enter-VsDevShell'
    filter_open_settings:
        CommandLine|contains|all:
            - '\AppData\Local\Packages\Microsoft.WindowsTerminal_'
            - '\LocalState\settings.json'
    filter_vsdevcmd:
        CommandLine|contains|all:
            - 'C:\Program Files\Microsoft Visual Studio\'
            - '\Common7\Tools\VsDevCmd.bat'
    condition: all of selection_* and not 1 of filter_*
falsepositives:
    - Other legitimate "Windows Terminal" profiles
level: medium
```
