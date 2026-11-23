---
title: Proxy Execution via Vshadow
summary: |-
  Detects the invocation of vshadow.exe with the -exec parameter that executes a specified script or command after the shadow copies are created but before the VShadow tool exits.
  VShadow is a command-line tool that you can use to create and manage volume shadow copies. While legitimate backup or administrative scripts may use this flag,
  attackers can leverage this parameter to proxy the execution of malware.
sigma_id: d7c75059-2901-4578-b209-8837fd31c6a8
status: experimental
level: medium
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1202
author: David Faiss
date: '2025-05-26'
falsepositives:
  - System backup or administrator tools
  - Legitimate administrative scripts
references:
  - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Vshadow/
  - https://learn.microsoft.com/en-us/windows/win32/vss/vshadow-tool-and-sample
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_vshadow_exec.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Proxy Execution via Vshadow
id: d7c75059-2901-4578-b209-8837fd31c6a8
status: experimental
description: |
    Detects the invocation of vshadow.exe with the -exec parameter that executes a specified script or command after the shadow copies are created but before the VShadow tool exits.
    VShadow is a command-line tool that you can use to create and manage volume shadow copies. While legitimate backup or administrative scripts may use this flag,
    attackers can leverage this parameter to proxy the execution of malware.
author: David Faiss
date: 2025-05-26
references:
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Vshadow/
    - https://learn.microsoft.com/en-us/windows/win32/vss/vshadow-tool-and-sample
tags:
    - attack.stealth
    - attack.t1202
logsource:
    product: windows
    category: process_creation
detection:
    selection_img:
        - Image|endswith: '\vshadow.exe'
        - OriginalFileName: 'vshadow.exe'
    selection_cli:
        CommandLine|contains: '-exec'
    condition: all of selection_*
falsepositives:
    - System backup or administrator tools
    - Legitimate administrative scripts
level: medium
```
