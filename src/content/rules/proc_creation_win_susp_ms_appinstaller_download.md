---
title: Potential File Download Via MS-AppInstaller Protocol Handler
summary: |-
  Detects usage of the "ms-appinstaller" protocol handler via command line to potentially download arbitrary files via AppInstaller.EXE
  The downloaded files are temporarily stored in ":\Users\%username%\AppData\Local\Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\AC\INetCache\<RANDOM-8-CHAR-DIRECTORY>"
sigma_id: 180c7c5c-d64b-4a63-86e9-68910451bc8b
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1218
author: Nasreddine Bencherchali (Nextron Systems), Swachchhanda Shrawan Poudel
date: '2023-11-09'
falsepositives:
  - Unknown
references:
  - https://lolbas-project.github.io/lolbas/Binaries/AppInstaller/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_susp_ms_appinstaller_download.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential File Download Via MS-AppInstaller Protocol Handler
id: 180c7c5c-d64b-4a63-86e9-68910451bc8b
related:
    - id: 7cff77e1-9663-46a3-8260-17f2e1aa9d0a
      type: derived
status: test
description: |
    Detects usage of the "ms-appinstaller" protocol handler via command line to potentially download arbitrary files via AppInstaller.EXE
    The downloaded files are temporarily stored in ":\Users\%username%\AppData\Local\Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\AC\INetCache\<RANDOM-8-CHAR-DIRECTORY>"
references:
    - https://lolbas-project.github.io/lolbas/Binaries/AppInstaller/
author: Nasreddine Bencherchali (Nextron Systems), Swachchhanda Shrawan Poudel
date: 2023-11-09
tags:
    - attack.execution
    - attack.stealth
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'ms-appinstaller://?source='
            - 'http'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
