---
title: Windows Binary Executed From WSL
summary: |-
  Detects the execution of Windows binaries from within a WSL instance.
  This could be used to masquerade parent-child relationships
sigma_id: ed825c86-c009-4014-b413-b76003e33d35
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1202
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-02-14'
falsepositives:
  - Unknown
references:
  - Internal Research
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_wsl_windows_binaries_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Windows Binary Executed From WSL
id: ed825c86-c009-4014-b413-b76003e33d35
status: test
description: |
    Detects the execution of Windows binaries from within a WSL instance.
    This could be used to masquerade parent-child relationships
references:
    - Internal Research
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-02-14
tags:
    - attack.execution
    - attack.stealth
    - attack.t1202
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|re: '[a-zA-Z]:\\'
        CurrentDirectory|contains: '\\\\wsl.localhost' # Note: programs not supporting UNC paths (example: cmd.exe). Will default to another location
    condition: selection
falsepositives:
    - Unknown
level: medium
```
