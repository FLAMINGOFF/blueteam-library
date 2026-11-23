---
title: Kaspersky Endpoint Security Stopped Via CommandLine - Linux
summary: |-
  Detects execution of the Kaspersky init.d stop script on Linux systems either directly or via systemctl.
  This activity may indicate a manual interruption of the antivirus service by an administrator, or it could be a sign of potential tampering or evasion attempts by malicious actors.
sigma_id: 36388120-b3f1-4ce9-b50b-280d9a7f4c04
status: experimental
level: high
platform: linux
logsource: linux / process_creation
tactics:
  - TA0002
  - TA0112
techniques:
  - T1685
author: Milad Cheraghi
date: '2025-10-18'
falsepositives:
  - System administrator manually stopping Kaspersky services
references:
  - https://support.kaspersky.com/KES4Linux/12.0.0/en-US/197929.htm
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_av_kaspersky_av_disabled.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Kaspersky Endpoint Security Stopped Via CommandLine - Linux
id: 36388120-b3f1-4ce9-b50b-280d9a7f4c04
status: experimental
description: |
  Detects execution of the Kaspersky init.d stop script on Linux systems either directly or via systemctl.
  This activity may indicate a manual interruption of the antivirus service by an administrator, or it could be a sign of potential tampering or evasion attempts by malicious actors.
references:
    - https://support.kaspersky.com/KES4Linux/12.0.0/en-US/197929.htm
author: Milad Cheraghi
date: 2025-10-18
tags:
    - attack.execution
    - attack.defense-impairment
    - attack.t1685
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith:
            # Note: Add the list of shells allowed in your environment that can be used to run init.d scripts.
            - '/systemctl'
            - '/bash'
            - '/sh'
        CommandLine|contains|all:
            - 'stop'
            - 'kesl'
    condition: selection
falsepositives:
    - System administrator manually stopping Kaspersky services
level: high
```
