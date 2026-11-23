---
title: Linux Setuid Capability Set on a Binary via Setcap Utility
summary: >-
  Detects the use of the 'setcap' utility to set the 'setuid' capability (cap_setuid) on a binary file.

  This capability allows a non privileged process to make arbitrary manipulations of user IDs (UIDs), including setting its current UID to a value that would otherwise be restricted (i.e. UID 0, the
  root user).

  This behavior can be used by adversaries to backdoor a binary in order to escalate privileges again in the future if needed.
sigma_id: ed447910-bc30-4575-a598-3a2e49516a7a
status: experimental
level: low
platform: linux
logsource: linux / process_creation
tactics:
  - TA0004
  - TA0003
techniques:
  - T1548
  - T1554
author: Luc Génaux
date: '2026-01-24'
falsepositives:
  - Unknown
references:
  - https://man7.org/linux/man-pages/man8/setcap.8.html
  - https://dfir.ch/posts/linux_capabilities/
  - https://juggernaut-sec.com/capabilities/#cap_setuid
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_cap_setuid.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Linux Setuid Capability Set on a Binary via Setcap Utility
id: ed447910-bc30-4575-a598-3a2e49516a7a
status: experimental
description: |
    Detects the use of the 'setcap' utility to set the 'setuid' capability (cap_setuid) on a binary file.
    This capability allows a non privileged process to make arbitrary manipulations of user IDs (UIDs), including setting its current UID to a value that would otherwise be restricted (i.e. UID 0, the root user).
    This behavior can be used by adversaries to backdoor a binary in order to escalate privileges again in the future if needed.
references:
    - https://man7.org/linux/man-pages/man8/setcap.8.html
    - https://dfir.ch/posts/linux_capabilities/
    - https://juggernaut-sec.com/capabilities/#cap_setuid
author: Luc Génaux
date: 2026-01-24
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.t1548
    - attack.t1554
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith: '/setcap'
        CommandLine|contains: 'cap_setuid'
    condition: selection
falsepositives:
    - Unknown
level: low
```
