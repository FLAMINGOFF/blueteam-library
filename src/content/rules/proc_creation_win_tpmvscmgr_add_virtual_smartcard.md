---
title: New Virtual Smart Card Created Via TpmVscMgr.EXE
summary: Detects execution of "Tpmvscmgr.exe" to create a new virtual smart card.
sigma_id: c633622e-cab9-4eaa-bb13-66a1d68b3e47
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques: []
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-06-15'
falsepositives:
  - Legitimate usage by an administrator
references:
  - https://learn.microsoft.com/en-us/windows/security/identity-protection/virtual-smart-cards/virtual-smart-card-tpmvscmgr
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_tpmvscmgr_add_virtual_smartcard.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: New Virtual Smart Card Created Via TpmVscMgr.EXE
id: c633622e-cab9-4eaa-bb13-66a1d68b3e47
status: test
description: Detects execution of "Tpmvscmgr.exe" to create a new virtual smart card.
references:
    - https://learn.microsoft.com/en-us/windows/security/identity-protection/virtual-smart-cards/virtual-smart-card-tpmvscmgr
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-06-15
tags:
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith: '\tpmvscmgr.exe'
        OriginalFileName: 'TpmVscMgr.exe'
    selection_cli:
        CommandLine|contains: 'create'
    condition: all of selection_*
falsepositives:
    - Legitimate usage by an administrator
level: medium
```
