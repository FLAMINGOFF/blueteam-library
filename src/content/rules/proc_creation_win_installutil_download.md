---
title: File Download Via InstallUtil.EXE
summary: Detects use of .NET InstallUtil.exe in order to download arbitrary files. The files will be written to "%LOCALAPPDATA%\Microsoft\Windows\INetCache\IE\"
sigma_id: 75edd216-1939-4c73-8d61-7f3a0d85b5cc
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1218
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-08-19'
modified: '2023-11-09'
falsepositives:
  - Unknown
references:
  - https://github.com/LOLBAS-Project/LOLBAS/pull/239
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_installutil_download.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: File Download Via InstallUtil.EXE
id: 75edd216-1939-4c73-8d61-7f3a0d85b5cc
status: test
description: |
    Detects use of .NET InstallUtil.exe in order to download arbitrary files. The files will be written to "%LOCALAPPDATA%\Microsoft\Windows\INetCache\IE\"
references:
    - https://github.com/LOLBAS-Project/LOLBAS/pull/239
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-19
modified: 2023-11-09
tags:
    - attack.stealth
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\InstallUtil.exe'
        - OriginalFileName: 'InstallUtil.exe'
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
