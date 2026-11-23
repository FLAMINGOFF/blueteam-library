---
title: Service Registry Key Deleted Via Reg.EXE
summary: Detects execution of "reg.exe" commands with the "delete" flag on services registry key. Often used by attacker to remove AV software services
sigma_id: 05b2aa93-1210-42c8-8d9a-2fcc13b284f5
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0112
techniques:
  - T1685
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-08-01'
modified: '2023-02-04'
falsepositives:
  - Unlikely
references:
  - https://www.virustotal.com/gui/file/2bcd5702a7565952c44075ac6fb946c7780526640d1264f692c7664c02c68465
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_reg_delete_services.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Service Registry Key Deleted Via Reg.EXE
id: 05b2aa93-1210-42c8-8d9a-2fcc13b284f5
status: test
description: Detects execution of "reg.exe" commands with the "delete" flag on services registry key. Often used by attacker to remove AV software services
references:
    - https://www.virustotal.com/gui/file/2bcd5702a7565952c44075ac6fb946c7780526640d1264f692c7664c02c68465
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-01
modified: 2023-02-04
tags:
    - attack.defense-impairment
    - attack.t1685
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: 'reg.exe'
        - OriginalFileName: 'reg.exe'
    selection_delete:
        CommandLine|contains: ' delete '
    selection_key:
        # Add specific services if you would like the rule to be more specific
        CommandLine|contains: '\SYSTEM\CurrentControlSet\services\'
    condition: all of selection_*
falsepositives:
    - Unlikely
level: high
```
