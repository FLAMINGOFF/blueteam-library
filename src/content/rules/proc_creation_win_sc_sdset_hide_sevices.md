---
title: Service DACL Abuse To Hide Services Via Sc.EXE
summary: Detects usage of the "sc.exe" utility adding a new service with special permission seen used by threat actors which makes the service hidden and unremovable.
sigma_id: a537cfc3-4297-4789-92b5-345bfd845ad0
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0003
  - TA0004
  - TA0002
  - TA0005
techniques:
  - T1574.011
author: Andreas Hunkeler (@Karneades)
date: '2021-12-20'
modified: '2022-08-08'
falsepositives:
  - Unknown
references:
  - https://blog.talosintelligence.com/2021/10/threat-hunting-in-large-datasets-by.html
  - https://www.sans.org/blog/red-team-tactics-hiding-windows-services/
  - https://twitter.com/Alh4zr3d/status/1580925761996828672
  - https://itconnect.uw.edu/tools-services-support/it-systems-infrastructure/msinf/other-help/understanding-sddl-syntax/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_sc_sdset_hide_sevices.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Service DACL Abuse To Hide Services Via Sc.EXE
id: a537cfc3-4297-4789-92b5-345bfd845ad0
related:
    - id: 99cf1e02-00fb-4c0d-8375-563f978dfd37 # Deny Service Access
      type: similar
    - id: 98c5aeef-32d5-492f-b174-64a691896d25 # Generic SD tampering
      type: similar
status: test
description: Detects usage of the "sc.exe" utility adding a new service with special permission seen used by threat actors which makes the service hidden and unremovable.
references:
    - https://blog.talosintelligence.com/2021/10/threat-hunting-in-large-datasets-by.html
    - https://www.sans.org/blog/red-team-tactics-hiding-windows-services/
    - https://twitter.com/Alh4zr3d/status/1580925761996828672
    - https://itconnect.uw.edu/tools-services-support/it-systems-infrastructure/msinf/other-help/understanding-sddl-syntax/
author: Andreas Hunkeler (@Karneades)
date: 2021-12-20
modified: 2022-08-08
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.execution
    - attack.stealth
    - attack.t1574.011
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\sc.exe'
        - OriginalFileName: 'sc.exe'
    selection_cli:
        CommandLine|contains|all:
            - 'sdset'
            # Summary of permissions
            #   DC: Delete All Child Objects
            #   LC: List Contents
            #   WP: Write All Properties
            #   DT: Delete Subtree
            #   SD: Delete
            - 'DCLCWPDTSD'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
