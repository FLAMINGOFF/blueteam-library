---
title: Audit Rules Deleted Via Auditctl
summary: |-
  Detects the execution of 'auditctl' with the '-D' command line parameter, which deletes all configured audit rules and watches on Linux systems.
  This technique is commonly used by attackers to disable audit logging and cover their tracks by removing monitoring capabilities.
  Removal of audit rules can significantly impair detection of malicious activities on the affected system.
sigma_id: bed26dea-4525-47f4-b24a-76e30e44ffb0
status: experimental
level: high
platform: linux
logsource: linux / process_creation
tactics: []
techniques:
  - T1685.004
author: Mohamed LAKRI
date: '2025-10-17'
falsepositives:
  - An administrator troubleshooting. Investigate all attempts.
references:
  - https://www.atomicredteam.io/atomic-red-team/atomics/T1562.012
  - https://linux.die.net/man/8/auditct
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_auditctl_clear_rules.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Audit Rules Deleted Via Auditctl
id: bed26dea-4525-47f4-b24a-76e30e44ffb0
status: experimental
description: |
    Detects the execution of 'auditctl' with the '-D' command line parameter, which deletes all configured audit rules and watches on Linux systems.
    This technique is commonly used by attackers to disable audit logging and cover their tracks by removing monitoring capabilities.
    Removal of audit rules can significantly impair detection of malicious activities on the affected system.
references:
    - https://www.atomicredteam.io/atomic-red-team/atomics/T1562.012
    - https://linux.die.net/man/8/auditct
author: Mohamed LAKRI
date: 2025-10-17
tags:
    - attack.defense-impairment
    - attack.t1685.004
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith: '/auditctl'
        CommandLine|re: '-D'
    condition: selection
falsepositives:
    - An administrator troubleshooting. Investigate all attempts.
level: high
```
