---
title: Use of Wfc.exe
summary: The Workflow Command-line Compiler can be used for AWL bypass and is listed in Microsoft's recommended block rules.
sigma_id: 49be8799-7b4d-4fda-ad23-cafbefdebbc5
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
  - TA0005
techniques:
  - T1127
author: Christopher Peacock @SecurePeacock, SCYTHE @scythe_io
date: '2022-06-01'
falsepositives:
  - Legitimate use by a software developer
references:
  - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Wfc/
  - https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/applications-that-can-bypass-wdac
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_lolbin_wfc.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Use of Wfc.exe
id: 49be8799-7b4d-4fda-ad23-cafbefdebbc5
status: test
description: The Workflow Command-line Compiler can be used for AWL bypass and is listed in Microsoft's recommended block rules.
references:
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Wfc/
    - https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/applications-that-can-bypass-wdac
author: 'Christopher Peacock @SecurePeacock, SCYTHE @scythe_io'
date: 2022-06-01
tags:
    - attack.execution
    - attack.stealth
    - attack.t1127
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\wfc.exe'
        - OriginalFileName: 'wfc.exe'
    condition: selection
falsepositives:
    - Legitimate use by a software developer
level: medium
```
