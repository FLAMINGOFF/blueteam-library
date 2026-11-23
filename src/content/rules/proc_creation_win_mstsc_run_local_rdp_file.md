---
title: Mstsc.EXE Execution With Local RDP File
summary: Detects potential RDP connection via Mstsc using a local ".rdp" file
sigma_id: 5fdce3ac-e7f9-4ecd-a3aa-a4d78ebbf0af
status: test
level: low
platform: windows
logsource: windows / process_creation
tactics:
  - TA0011
techniques:
  - T1219.002
author: Nasreddine Bencherchali (Nextron Systems), Christopher Peacock @securepeacock
date: '2023-04-18'
modified: '2023-04-30'
falsepositives:
  - Likely with legitimate usage of ".rdp" files
references:
  - https://www.blackhillsinfosec.com/rogue-rdp-revisiting-initial-access-methods/
  - https://web.archive.org/web/20230726144748/https://blog.thickmints.dev/mintsights/detecting-rogue-rdp/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_mstsc_run_local_rdp_file.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Mstsc.EXE Execution With Local RDP File
id: 5fdce3ac-e7f9-4ecd-a3aa-a4d78ebbf0af
status: test
description: Detects potential RDP connection via Mstsc using a local ".rdp" file
references:
    - https://www.blackhillsinfosec.com/rogue-rdp-revisiting-initial-access-methods/
    - https://web.archive.org/web/20230726144748/https://blog.thickmints.dev/mintsights/detecting-rogue-rdp/
author: Nasreddine Bencherchali (Nextron Systems), Christopher Peacock @securepeacock
date: 2023-04-18
modified: 2023-04-30
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
    selection_cli:
        CommandLine|endswith:
            - '.rdp'
            - '.rdp"'
    filter_optional_wsl:
        ParentImage: 'C:\Windows\System32\lxss\wslhost.exe'
        CommandLine|contains: 'C:\ProgramData\Microsoft\WSL\wslg.rdp'
    condition: all of selection_* and not 1 of filter_optional_*
falsepositives:
    - Likely with legitimate usage of ".rdp" files
level: low
```
