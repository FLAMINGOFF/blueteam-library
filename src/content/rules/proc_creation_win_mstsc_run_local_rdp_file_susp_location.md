---
title: Suspicious Mstsc.EXE Execution With Local RDP File
summary: Detects potential RDP connection via Mstsc using a local ".rdp" file located in suspicious locations.
sigma_id: 6e22722b-dfb1-4508-a911-49ac840b40f8
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0011
techniques:
  - T1219.002
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-04-18'
falsepositives:
  - Likelihood is related to how often the paths are used in the environment
references:
  - https://www.blackhillsinfosec.com/rogue-rdp-revisiting-initial-access-methods/
  - https://web.archive.org/web/20230726144748/https://blog.thickmints.dev/mintsights/detecting-rogue-rdp/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_mstsc_run_local_rdp_file_susp_location.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Mstsc.EXE Execution With Local RDP File
id: 6e22722b-dfb1-4508-a911-49ac840b40f8
status: test
description: Detects potential RDP connection via Mstsc using a local ".rdp" file located in suspicious locations.
references:
    - https://www.blackhillsinfosec.com/rogue-rdp-revisiting-initial-access-methods/
    - https://web.archive.org/web/20230726144748/https://blog.thickmints.dev/mintsights/detecting-rogue-rdp/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-04-18
tags:
    - attack.command-and-control
    - attack.t1219.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\mstsc.exe'
        - OriginalFileName: 'mstsc.exe'
    selection_extension:
        CommandLine|endswith:
            - '.rdp'
            - '.rdp"'
    selection_paths:
        # Note: This list of paths is better transformed into a whitelist where you only exclude legitimate locations you use in your env
        CommandLine|contains:
            - ':\Users\Public\'
            - ':\Windows\System32\spool\drivers\color'
            - ':\Windows\System32\Tasks_Migrated '
            - ':\Windows\Tasks\'
            - ':\Windows\Temp\'
            - ':\Windows\Tracing\'
            - '\AppData\Local\Temp\'
            # - '\Desktop\' # Could be source of FP depending on the environment
            - '\Downloads\' # Could be source of FP depending on the environment
    condition: all of selection_*
falsepositives:
    - Likelihood is related to how often the paths are used in the environment
level: high
```
