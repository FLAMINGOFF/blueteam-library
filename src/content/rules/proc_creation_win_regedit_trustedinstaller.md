---
title: Regedit as Trusted Installer
summary: Detects a regedit started with TrustedInstaller privileges or by ProcessHacker.exe
sigma_id: 883835a7-df45-43e4-bf1d-4268768afda4
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
techniques:
  - T1548
author: Florian Roth (Nextron Systems)
date: '2021-05-27'
modified: '2022-10-09'
falsepositives:
  - Unlikely
references:
  - https://twitter.com/1kwpeter/status/1397816101455765504
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_regedit_trustedinstaller.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Regedit as Trusted Installer
id: 883835a7-df45-43e4-bf1d-4268768afda4
status: test
description: Detects a regedit started with TrustedInstaller privileges or by ProcessHacker.exe
references:
    - https://twitter.com/1kwpeter/status/1397816101455765504
author: Florian Roth (Nextron Systems)
date: 2021-05-27
modified: 2022-10-09
tags:
    - attack.privilege-escalation
    - attack.t1548
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\regedit.exe'
        ParentImage|endswith:
            - '\TrustedInstaller.exe'
            - '\ProcessHacker.exe'
    condition: selection
falsepositives:
    - Unlikely
level: high
```
