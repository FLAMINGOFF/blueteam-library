---
title: Potential Linux Process Code Injection Via DD Utility
summary: Detects the injection of code by overwriting the memory map of a Linux process using the "dd" Linux command.
sigma_id: 4cad6c64-d6df-42d6-8dae-eb78defdc415
status: test
level: medium
platform: linux
logsource: linux / process_creation
tactics:
  - TA0004
techniques:
  - T1055.009
author: Joseph Kamau
date: '2023-12-01'
falsepositives:
  - Unknown
references:
  - https://www.aon.com/cyber-solutions/aon_cyber_labs/linux-based-inter-process-code-injection-without-ptrace2/
  - https://github.com/AonCyberLabs/Cexigua/blob/34d338620afae4c6335ba8d8d499e1d7d3d5d7b5/overwrite.sh
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_dd_process_injection.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential Linux Process Code Injection Via DD Utility
id: 4cad6c64-d6df-42d6-8dae-eb78defdc415
status: test
description: Detects the injection of code by overwriting the memory map of a Linux process using the "dd" Linux command.
references:
    - https://www.aon.com/cyber-solutions/aon_cyber_labs/linux-based-inter-process-code-injection-without-ptrace2/
    - https://github.com/AonCyberLabs/Cexigua/blob/34d338620afae4c6335ba8d8d499e1d7d3d5d7b5/overwrite.sh
author: Joseph Kamau
date: 2023-12-01
tags:
    - attack.privilege-escalation
    - attack.stealth
    - attack.t1055.009
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith: '/dd'
        CommandLine|contains|all:
            - 'of='
            - '/proc/'
            - '/mem'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
