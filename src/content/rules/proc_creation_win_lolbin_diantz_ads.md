---
title: Suspicious Diantz Alternate Data Stream Execution
summary: Compress target file into a cab file stored in the Alternate Data Stream (ADS) of the target file.
sigma_id: 6b369ced-4b1d-48f1-b427-fdc0de0790bd
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
modified: '2022-12-31'
falsepositives:
  - Very Possible
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Diantz/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_lolbin_diantz_ads.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Diantz Alternate Data Stream Execution
id: 6b369ced-4b1d-48f1-b427-fdc0de0790bd
status: test
description: Compress target file into a cab file stored in the Alternate Data Stream (ADS) of the target file.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Diantz/
author: frack113
date: 2021-11-26
modified: 2022-12-31
tags:
    - attack.stealth
    - attack.t1564.004
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - diantz.exe
            - .cab
        CommandLine|re: ':[^\\]'
    condition: selection
falsepositives:
    - Very Possible
level: medium
```
