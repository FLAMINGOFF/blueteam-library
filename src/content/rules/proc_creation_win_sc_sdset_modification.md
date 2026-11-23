---
title: Service Security Descriptor Tampering Via Sc.EXE
summary: Detection of sc.exe utility adding a new service with special permission which hides that service.
sigma_id: 98c5aeef-32d5-492f-b174-64a691896d25
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0003
  - TA0004
  - TA0002
  - TA0005
techniques:
  - T1574.011
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-02-28'
falsepositives:
  - Unknown
references:
  - https://blog.talosintelligence.com/2021/10/threat-hunting-in-large-datasets-by.html
  - https://www.sans.org/blog/red-team-tactics-hiding-windows-services/
  - https://twitter.com/Alh4zr3d/status/1580925761996828672
  - https://twitter.com/0gtweet/status/1628720819537936386
  - https://itconnect.uw.edu/tools-services-support/it-systems-infrastructure/msinf/other-help/understanding-sddl-syntax/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_sc_sdset_modification.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Service Security Descriptor Tampering Via Sc.EXE
id: 98c5aeef-32d5-492f-b174-64a691896d25
related:
    - id: 99cf1e02-00fb-4c0d-8375-563f978dfd37 # Deny Service Access
      type: similar
    - id: a537cfc3-4297-4789-92b5-345bfd845ad0 # Specific Technique
      type: similar
status: test
description: Detection of sc.exe utility adding a new service with special permission which hides that service.
references:
    - https://blog.talosintelligence.com/2021/10/threat-hunting-in-large-datasets-by.html
    - https://www.sans.org/blog/red-team-tactics-hiding-windows-services/
    - https://twitter.com/Alh4zr3d/status/1580925761996828672
    - https://twitter.com/0gtweet/status/1628720819537936386
    - https://itconnect.uw.edu/tools-services-support/it-systems-infrastructure/msinf/other-help/understanding-sddl-syntax/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-02-28
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
        CommandLine|contains: 'sdset'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_sc_sdset_modification/info.yml
```
