---
title: Function Call From Undocumented COM Interface EditionUpgradeManager
summary: Detects function calls from the EditionUpgradeManager COM interface. Which is an interface that is not used by standard executables.
sigma_id: fb3722e4-1a06-46b6-b772-253e2e7db933
status: test
level: medium
platform: windows
logsource: windows / process_access
tactics:
  - TA0004
techniques:
  - T1548.002
author: oscd.community, Dmitry Uchakin
date: '2020-10-07'
modified: '2023-11-30'
falsepositives:
  - Unknown
references:
  - https://www.snip2code.com/Snippet/4397378/UAC-bypass-using-EditionUpgradeManager-C/
  - https://gist.github.com/hfiref0x/de9c83966623236f5ebf8d9ae2407611
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_access/proc_access_win_uac_bypass_editionupgrademanagerobj.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Function Call From Undocumented COM Interface EditionUpgradeManager
id: fb3722e4-1a06-46b6-b772-253e2e7db933
status: test
description: Detects function calls from the EditionUpgradeManager COM interface. Which is an interface that is not used by standard executables.
references:
    - https://www.snip2code.com/Snippet/4397378/UAC-bypass-using-EditionUpgradeManager-C/
    - https://gist.github.com/hfiref0x/de9c83966623236f5ebf8d9ae2407611
author: oscd.community, Dmitry Uchakin
date: 2020-10-07
modified: 2023-11-30
tags:
    - attack.privilege-escalation
    - attack.t1548.002
logsource:
    category: process_access
    product: windows
detection:
    selection:
        CallTrace|contains: 'editionupgrademanagerobj.dll'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
