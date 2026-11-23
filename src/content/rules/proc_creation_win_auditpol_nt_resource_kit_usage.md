---
title: Audit Policy Tampering Via NT Resource Kit Auditpol
summary: |-
  Threat actors can use an older version of the auditpol binary available inside the NT resource kit to change audit policy configuration to impair detection capability.
  This can be carried out by selectively disabling/removing certain audit policies as well as restoring a custom policy owned by the threat actor.
sigma_id: c6c56ada-612b-42d1-9a29-adad3c5c2c1e
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0112
techniques:
  - T1685.001
author: Nasreddine Bencherchali (Nextron Systems)
date: '2021-12-18'
modified: '2023-02-21'
falsepositives:
  - >-
    The old auditpol utility isn't available by default on recent versions of Windows as it was replaced by a newer version. The FP rate should be very low except for tools that use a similar flag
    structure
references:
  - https://github.com/3CORESec/MAL-CL/tree/master/Descriptors/Windows%202000%20Resource%20Kit%20Tools/AuditPol
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_auditpol_nt_resource_kit_usage.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Audit Policy Tampering Via NT Resource Kit Auditpol
id: c6c56ada-612b-42d1-9a29-adad3c5c2c1e
related:
    - id: 0a13e132-651d-11eb-ae93-0242ac130002 # New auditpol version
      type: similar
status: test
description: |
    Threat actors can use an older version of the auditpol binary available inside the NT resource kit to change audit policy configuration to impair detection capability.
    This can be carried out by selectively disabling/removing certain audit policies as well as restoring a custom policy owned by the threat actor.
references:
    - https://github.com/3CORESec/MAL-CL/tree/master/Descriptors/Windows%202000%20Resource%20Kit%20Tools/AuditPol
author: Nasreddine Bencherchali (Nextron Systems)
date: 2021-12-18
modified: 2023-02-21
tags:
    - attack.defense-impairment
    - attack.t1685.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - '/logon:none'
            - '/system:none'
            - '/sam:none'
            - '/privilege:none'
            - '/object:none'
            - '/process:none'
            - '/policy:none'
    condition: selection
falsepositives:
    - The old auditpol utility isn't available by default on recent versions of Windows as it was replaced by a newer version. The FP rate should be very low except for tools that use a similar flag structure
level: high
```
