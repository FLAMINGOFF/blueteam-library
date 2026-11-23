---
title: Possible Privilege Escalation via Weak Service Permissions
summary: Detection of sc.exe utility spawning by user with Medium integrity level to change service ImagePath or FailureCommand
sigma_id: d937b75f-a665-4480-88a5-2f20e9f9b22a
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
author: Teymur Kheirkhabarov
date: '2019-10-26'
modified: '2024-12-01'
falsepositives:
  - Unknown
references:
  - https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment
  - https://pentestlab.blog/2017/03/30/weak-service-permissions/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_sc_change_sevice_image_path_by_non_admin.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Possible Privilege Escalation via Weak Service Permissions
id: d937b75f-a665-4480-88a5-2f20e9f9b22a
status: test
description: Detection of sc.exe utility spawning by user with Medium integrity level to change service ImagePath or FailureCommand
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment
    - https://pentestlab.blog/2017/03/30/weak-service-permissions/
author: Teymur Kheirkhabarov
date: 2019-10-26
modified: 2024-12-01
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
    scbynonadmin:
        Image|endswith: '\sc.exe'
        IntegrityLevel:
            - 'Medium'
            - 'S-1-16-8192'
    selection_binpath:
        CommandLine|contains|all:
            - 'config'
            - 'binPath'
    selection_failure:
        CommandLine|contains|all:
            - 'failure'
            - 'command'
    condition: scbynonadmin and 1 of selection_*
falsepositives:
    - Unknown
level: high
```
