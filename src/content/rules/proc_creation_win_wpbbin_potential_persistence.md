---
title: UEFI Persistence Via Wpbbin - ProcessCreation
summary: Detects execution of the binary "wpbbin" which is used as part of the UEFI based persistence method described in the reference section
sigma_id: 4abc0ec4-db5a-412f-9632-26659cddf145
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0003
techniques:
  - T1542.001
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-07-18'
falsepositives:
  - Legitimate usage of the file by hardware manufacturer such as lenovo (Thanks @0gtweet for the tip)
references:
  - https://grzegorztworek.medium.com/using-uefi-to-inject-executable-files-into-bitlocker-protected-drives-8ff4ca59c94c
  - https://persistence-info.github.io/Data/wpbbin.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_wpbbin_potential_persistence.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: UEFI Persistence Via Wpbbin - ProcessCreation
id: 4abc0ec4-db5a-412f-9632-26659cddf145
status: test
description: Detects execution of the binary "wpbbin" which is used as part of the UEFI based persistence method described in the reference section
references:
    - https://grzegorztworek.medium.com/using-uefi-to-inject-executable-files-into-bitlocker-protected-drives-8ff4ca59c94c
    - https://persistence-info.github.io/Data/wpbbin.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-07-18
tags:
    - attack.persistence
    - attack.stealth
    - attack.t1542.001
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image: 'C:\Windows\System32\wpbbin.exe'
    condition: selection
falsepositives:
    - Legitimate usage of the file by hardware manufacturer such as lenovo (Thanks @0gtweet for the tip)
level: high
```
