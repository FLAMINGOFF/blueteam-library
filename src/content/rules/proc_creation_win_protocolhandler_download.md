---
title: File Download Using ProtocolHandler.exe
summary: Detects usage of "ProtocolHandler" to download files. Downloaded files will be located in the cache folder (for example - %LOCALAPPDATA%\Microsoft\Windows\INetCache\IE)
sigma_id: 104cdb48-a7a8-4ca7-a453-32942c6e5dcb
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1218
author: frack113
date: '2021-07-13'
modified: '2023-11-09'
falsepositives:
  - Unknown
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1218/T1218.md
  - https://lolbas-project.github.io/lolbas/OtherMSBinaries/ProtocolHandler/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_protocolhandler_download.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: File Download Using ProtocolHandler.exe
id: 104cdb48-a7a8-4ca7-a453-32942c6e5dcb
status: test
description: |
    Detects usage of "ProtocolHandler" to download files. Downloaded files will be located in the cache folder (for example - %LOCALAPPDATA%\Microsoft\Windows\INetCache\IE)
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1218/T1218.md
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/ProtocolHandler/
author: frack113
date: 2021-07-13
modified: 2023-11-09
tags:
    - attack.stealth
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\protocolhandler.exe'
        - OriginalFileName: 'ProtocolHandler.exe'
    selection_cli:
        CommandLine|contains:
            - 'ftp://'
            - 'http://'
            - 'https://'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```
