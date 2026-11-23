---
title: Suspicious Extrac32 Alternate Data Stream Execution
summary: Extract data from cab file and hide it in an alternate data stream
sigma_id: 4b13db67-0c45-40f1-aba8-66a1a7198a1e
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques:
  - T1564.004
author: frack113
date: '2021-11-26'
modified: '2022-12-30'
falsepositives:
  - Unknown
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Extrac32/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_lolbin_extrac32_ads.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Extrac32 Alternate Data Stream Execution
id: 4b13db67-0c45-40f1-aba8-66a1a7198a1e
status: test
description: Extract data from cab file and hide it in an alternate data stream
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Extrac32/
author: frack113
date: 2021-11-26
modified: 2022-12-30
tags:
    - attack.stealth
    - attack.t1564.004
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - extrac32.exe
            - .cab
        CommandLine|re: ':[^\\]'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
