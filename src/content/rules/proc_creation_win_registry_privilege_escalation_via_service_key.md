---
title: Potential Privilege Escalation via Service Permissions Weakness
summary: Detect modification of services configuration (ImagePath, FailureCommand and ServiceDLL) in registry by processes with Medium integrity level
sigma_id: 0f9c21f1-6a73-4b0e-9809-cb562cb8d981
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0003
  - TA0004
  - TA0002
techniques:
  - T1574.011
author: Teymur Kheirkhabarov
date: '2019-10-26'
modified: '2024-12-01'
falsepositives:
  - Unknown
references:
  - https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment
  - https://pentestlab.blog/2017/03/31/insecure-registry-permissions/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_registry_privilege_escalation_via_service_key.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential Privilege Escalation via Service Permissions Weakness
id: 0f9c21f1-6a73-4b0e-9809-cb562cb8d981
status: test
description: Detect modification of services configuration (ImagePath, FailureCommand and ServiceDLL) in registry by processes with Medium integrity level
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment
    - https://pentestlab.blog/2017/03/31/insecure-registry-permissions/
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
    product: windows
    category: process_creation
detection:
    selection:
        IntegrityLevel:
            - 'Medium'
            - 'S-1-16-8192'
        CommandLine|contains|all:
            - 'ControlSet'
            - 'services'
        CommandLine|contains:
            - '\ImagePath'
            - '\FailureCommand'
            - '\ServiceDll'
    condition: selection
falsepositives:
    - Unknown
level: high
```
