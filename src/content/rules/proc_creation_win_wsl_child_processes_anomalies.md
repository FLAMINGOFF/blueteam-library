---
title: WSL Child Process Anomaly
summary: Detects uncommon or suspicious child processes spawning from a WSL process. This could indicate an attempt to evade parent/child relationship detections or persistence attempts via cron using WSL
sigma_id: 2267fe65-0681-42ad-9a6d-46553d3f3480
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1218
  - T1202
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-01-23'
modified: '2023-08-15'
falsepositives:
  - Unknown
references:
  - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Wsl/
  - https://twitter.com/nas_bench/status/1535431474429808642
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_wsl_child_processes_anomalies.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: WSL Child Process Anomaly
id: 2267fe65-0681-42ad-9a6d-46553d3f3480
related:
    - id: dec44ca7-61ad-493c-bfd7-8819c5faa09b # LOLBIN Rule
      type: derived
status: test
description: Detects uncommon or suspicious child processes spawning from a WSL process. This could indicate an attempt to evade parent/child relationship detections or persistence attempts via cron using WSL
references:
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Wsl/
    - https://twitter.com/nas_bench/status/1535431474429808642
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-01-23
modified: 2023-08-15
tags:
    - attack.execution
    - attack.stealth
    - attack.t1218
    - attack.t1202
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\wsl.exe'
            - '\wslhost.exe'
    selection_children_images:
        Image|endswith:
            # Add more suspicious/uncommon "lolbin" processes
            - '\calc.exe'
            - '\cmd.exe'
            - '\cscript.exe'
            - '\mshta.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\regsvr32.exe'
            - '\rundll32.exe'
            - '\wscript.exe'
    selection_children_paths:
        Image|contains:
            - '\AppData\Local\Temp\'
            - 'C:\Users\Public\'
            - 'C:\Windows\Temp\'
            - 'C:\Temp\'
            - '\Downloads\'
            - '\Desktop\'
    condition: selection_parent and 1 of selection_children_*
falsepositives:
    - Unknown
level: medium
```
