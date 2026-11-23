---
title: Linux Recon Indicators
summary: Detects events with patterns found in commands used for reconnaissance on linux systems
sigma_id: 0cf7a157-8879-41a2-8f55-388dd23746b7
status: test
level: high
platform: linux
logsource: linux / process_creation
tactics:
  - TA0043
  - TA0006
techniques:
  - T1592.004
  - T1552.001
author: Florian Roth (Nextron Systems)
date: '2022-06-20'
falsepositives:
  - Legitimate administration activities
references:
  - https://github.com/sleventyeleven/linuxprivchecker/blob/0d701080bbf92efd464e97d71a70f97c6f2cd658/linuxprivchecker.py
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_susp_recon_indicators.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Linux Recon Indicators
id: 0cf7a157-8879-41a2-8f55-388dd23746b7
status: test
description: Detects events with patterns found in commands used for reconnaissance on linux systems
references:
    - https://github.com/sleventyeleven/linuxprivchecker/blob/0d701080bbf92efd464e97d71a70f97c6f2cd658/linuxprivchecker.py
author: Florian Roth (Nextron Systems)
date: 2022-06-20
tags:
    - attack.reconnaissance
    - attack.t1592.004
    - attack.credential-access
    - attack.t1552.001
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains:
            - ' -name .htpasswd'
            - ' -perm -4000 '
    condition: selection
falsepositives:
    - Legitimate administration activities
level: high
```
