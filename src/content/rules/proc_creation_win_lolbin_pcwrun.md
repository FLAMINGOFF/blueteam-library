---
title: Indirect Command Execution By Program Compatibility Wizard
summary: Detect indirect command execution via Program Compatibility Assistant pcwrun.exe
sigma_id: b97cd4b1-30b8-4a9d-bd72-6293928d52bc
status: test
level: low
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1218
author: A. Sungurov , oscd.community
date: '2020-10-12'
modified: '2021-11-27'
falsepositives:
  - Need to use extra processing with 'unique_count' / 'filter' to focus on outliers as opposed to commonly seen artifacts
  - Legit usage of scripts
references:
  - https://twitter.com/pabraeken/status/991335019833708544
  - https://lolbas-project.github.io/lolbas/Binaries/Pcwrun/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_lolbin_pcwrun.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Indirect Command Execution By Program Compatibility Wizard
id: b97cd4b1-30b8-4a9d-bd72-6293928d52bc
status: test
description: Detect indirect command execution via Program Compatibility Assistant pcwrun.exe
references:
    - https://twitter.com/pabraeken/status/991335019833708544
    - https://lolbas-project.github.io/lolbas/Binaries/Pcwrun/
author: A. Sungurov , oscd.community
date: 2020-10-12
modified: 2021-11-27
tags:
    - attack.stealth
    - attack.t1218
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\pcwrun.exe'
    condition: selection
falsepositives:
    - Need to use extra processing with 'unique_count' / 'filter' to focus on outliers as opposed to commonly seen artifacts
    - Legit usage of scripts
level: low
```
