---
title: Non-privileged Usage of Reg or Powershell
summary: Search for usage of reg or Powershell by non-privileged users to modify service configuration in registry
sigma_id: 8f02c935-effe-45b3-8fc9-ef8696a9e41d
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0003
techniques:
  - T1112
author: Teymur Kheirkhabarov (idea), Ryan Plas (rule), oscd.community
date: '2020-10-05'
modified: '2024-12-01'
falsepositives:
  - Unknown
references:
  - https://image.slidesharecdn.com/kheirkhabarovoffzonefinal-181117201458/95/hunting-for-privilege-escalation-in-windows-environment-20-638.jpg
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_susp_non_priv_reg_or_ps.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Non-privileged Usage of Reg or Powershell
id: 8f02c935-effe-45b3-8fc9-ef8696a9e41d
status: test
description: Search for usage of reg or Powershell by non-privileged users to modify service configuration in registry
references:
    - https://image.slidesharecdn.com/kheirkhabarovoffzonefinal-181117201458/95/hunting-for-privilege-escalation-in-windows-environment-20-638.jpg
author: Teymur Kheirkhabarov (idea), Ryan Plas (rule), oscd.community
date: 2020-10-05
modified: 2024-12-01
tags:
    - attack.persistence
    - attack.defense-impairment
    - attack.t1112
logsource:
    category: process_creation
    product: windows
detection:
    selection_cli:
        - CommandLine|contains|all:
              - 'reg '
              - 'add'
        - CommandLine|contains:
              - 'powershell'
              - 'set-itemproperty'
              - ' sp '
              - 'new-itemproperty'
    selection_data:
        IntegrityLevel:
            - 'Medium'
            - 'S-1-16-8192'
        CommandLine|contains|all:
            - 'ControlSet'
            - 'Services'
        CommandLine|contains:
            - 'ImagePath'
            - 'FailureCommand'
            - 'ServiceDLL'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
