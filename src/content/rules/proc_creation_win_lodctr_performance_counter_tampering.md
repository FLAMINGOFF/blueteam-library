---
title: Rebuild Performance Counter Values Via Lodctr.EXE
summary: >-
  Detects the execution of "lodctr.exe" to rebuild the performance counter registry values. This can be abused by attackers by providing a malicious config file to overwrite performance counter
  configuration to confuse and evade monitoring and security solutions.
sigma_id: cc9d3712-6310-4320-b2df-7cb408274d53
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques: []
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-06-15'
modified: '2024-03-05'
falsepositives:
  - Legitimate usage by an administrator
references:
  - https://learn.microsoft.com/en-us/windows/security/identity-protection/virtual-smart-cards/virtual-smart-card-tpmvscmgr
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_lodctr_performance_counter_tampering.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Rebuild Performance Counter Values Via Lodctr.EXE
id: cc9d3712-6310-4320-b2df-7cb408274d53
status: test
description: Detects the execution of "lodctr.exe" to rebuild the performance counter registry values. This can be abused by attackers by providing a malicious config file to overwrite performance counter configuration to confuse and evade monitoring and security solutions.
references:
    - https://learn.microsoft.com/en-us/windows/security/identity-protection/virtual-smart-cards/virtual-smart-card-tpmvscmgr
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-06-15
modified: 2024-03-05
tags:
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith: '\lodctr.exe'
        OriginalFileName: 'LODCTR.EXE'
    selection_cli:
        CommandLine|contains|windash: ' -r'
    condition: all of selection_*
falsepositives:
    - Legitimate usage by an administrator
level: medium
```
