---
title: Installation of WSL Kali-Linux
summary: |-
  Detects installation of Kali Linux distribution through Windows Subsystem for Linux (WSL).
  Attackers may use Kali Linux WSL to leverage its penetration testing tools and capabilities for malicious purposes.
sigma_id: eca8ae39-5c3c-4321-b538-9e64fe25822e
status: experimental
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1059
author: Swachchhanda Shrawan Poudel (Nextron Systems)
date: '2025-10-10'
falsepositives:
  - Legitimate installation or usage of Kali Linux WSL by administrators or security teams
references:
  - https://medium.com/@redfanatic7/running-kali-linux-on-windows-51ad95166e6e
  - https://learn.microsoft.com/en-us/windows/wsl/install
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_wsl_kali_linux_installation.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Installation of WSL Kali-Linux
id: eca8ae39-5c3c-4321-b538-9e64fe25822e
status: experimental
description: |
    Detects installation of Kali Linux distribution through Windows Subsystem for Linux (WSL).
    Attackers may use Kali Linux WSL to leverage its penetration testing tools and capabilities for malicious purposes.
references:
    - https://medium.com/@redfanatic7/running-kali-linux-on-windows-51ad95166e6e
    - https://learn.microsoft.com/en-us/windows/wsl/install
author: Swachchhanda Shrawan Poudel (Nextron Systems)
date: 2025-10-10
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection_wsl_img:
        - Image|endswith: '\wsl.exe'
        - OriginalFileName: 'wsl'
    selection_wsl_install:
        CommandLine|contains:
            - ' --install '
            - ' -i '
    selection_wsl_kali:
        CommandLine|contains: 'kali'
    condition: all of selection_wsl_*
falsepositives:
    - Legitimate installation or usage of Kali Linux WSL by administrators or security teams
level: high
```
