---
title: Suspicious Driver Install by pnputil.exe
summary: Detects when a possible suspicious driver is being installed via pnputil.exe lolbin
sigma_id: a2ea3ae7-d3d0-40a0-a55c-25a45c87cac1
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
  - TA0003
techniques:
  - T1547
author: Hai Vaknin @LuxNoBulIshit, Avihay eldad  @aloneliassaf, Austin Songer @austinsonger
date: '2021-09-30'
modified: '2022-10-09'
falsepositives:
  - Pnputil.exe being used may be performed by a system administrator.
  - Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
  - Pnputil.exe being executed from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
references:
  - https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/pnputil-command-syntax
  - https://strontic.github.io/xcyclopedia/library/pnputil.exe-60EDC5E6BDBAEE441F2E3AEACD0340D2.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_lolbin_susp_driver_installed_by_pnputil.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Driver Install by pnputil.exe
id: a2ea3ae7-d3d0-40a0-a55c-25a45c87cac1
status: test
description: Detects when a possible suspicious driver is being installed via pnputil.exe lolbin
references:
    - https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/pnputil-command-syntax
    - https://strontic.github.io/xcyclopedia/library/pnputil.exe-60EDC5E6BDBAEE441F2E3AEACD0340D2.html
author: Hai Vaknin @LuxNoBulIshit, Avihay eldad  @aloneliassaf, Austin Songer @austinsonger
date: 2021-09-30
modified: 2022-10-09
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.t1547
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - '-i'
            - '/install'
            - '-a'
            - '/add-driver'
            - '.inf'
        Image|endswith: '\pnputil.exe'
    condition: selection
falsepositives:
    - Pnputil.exe being used may be performed by a system administrator.
    - Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
    - Pnputil.exe being executed from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
level: medium
```
