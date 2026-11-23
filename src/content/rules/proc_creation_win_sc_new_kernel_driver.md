---
title: New Kernel Driver Via SC.EXE
summary: Detects creation of a new service (kernel driver) with the type "kernel"
sigma_id: 431a1fdb-4799-4f3b-91c3-a683b003fc49
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0003
  - TA0004
techniques:
  - T1543.003
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-07-14'
modified: '2025-10-07'
falsepositives:
  - Rare legitimate installation of kernel drivers via sc.exe
references:
  - https://www.aon.com/cyber-solutions/aon_cyber_labs/yours-truly-signed-av-driver-weaponizing-an-antivirus-driver/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_sc_new_kernel_driver.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: New Kernel Driver Via SC.EXE
id: 431a1fdb-4799-4f3b-91c3-a683b003fc49
status: test
description: Detects creation of a new service (kernel driver) with the type "kernel"
references:
    - https://www.aon.com/cyber-solutions/aon_cyber_labs/yours-truly-signed-av-driver-weaponizing-an-antivirus-driver/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-07-14
modified: 2025-10-07
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1543.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\sc.exe'
        CommandLine|contains:
            - 'create'
            - 'config'
        CommandLine|contains|all:
            - 'binPath'
            - 'type'
            - 'kernel'
    filter_optional_avira_driver:
        - CommandLine|contains|all:
              - 'create netprotection_network_filter'
              - 'type= kernel start= '
              - 'binPath= System32\drivers\netprotection_network_filter'
              - 'DisplayName= netprotection_network_filter'
              - 'group= PNP_TDI tag= yes'
        - CommandLine|contains|all:
              - 'create avelam binpath=C:\Windows\system32\drivers\avelam.sys'
              - 'type=kernel start=boot error=critical group=Early-Launch'
    condition: selection and not 1 of filter_optional_*
falsepositives:
    - Rare legitimate installation of kernel drivers via sc.exe
level: medium
```
