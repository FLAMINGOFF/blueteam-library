---
title: Suspicious Execution of InstallUtil Without Log
summary: Uses the .NET InstallUtil.exe application in order to execute image without log
sigma_id: d042284c-a296-4988-9be5-f424fadcc28c
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics: []
techniques: []
author: frack113
date: '2022-01-23'
modified: '2022-02-04'
falsepositives:
  - Unknown
references:
  - https://securelist.com/moonbounce-the-dark-side-of-uefi-firmware/105468/
  - https://learn.microsoft.com/en-us/dotnet/framework/tools/installutil-exe-installer-tool
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_instalutil_no_log_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Execution of InstallUtil Without Log
id: d042284c-a296-4988-9be5-f424fadcc28c
status: test
description: Uses the .NET InstallUtil.exe application in order to execute image without log
references:
    - https://securelist.com/moonbounce-the-dark-side-of-uefi-firmware/105468/
    - https://learn.microsoft.com/en-us/dotnet/framework/tools/installutil-exe-installer-tool
author: frack113
date: 2022-01-23
modified: 2022-02-04
tags:
    - attack.stealth
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\InstallUtil.exe'
        Image|contains: 'Microsoft.NET\Framework'
        CommandLine|contains|all:
            - '/logfile= '
            - '/LogToConsole=false'
    condition: selection
falsepositives:
    - Unknown
level: medium
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_instalutil_no_log_execution/info.yml
```
