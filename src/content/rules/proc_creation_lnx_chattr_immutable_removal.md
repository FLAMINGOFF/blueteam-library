---
title: Remove Immutable File Attribute
summary: Detects usage of the 'chattr' utility to remove immutable file attribute.
sigma_id: 34979410-e4b5-4e5d-8cfb-389fdff05c12
status: test
level: medium
platform: linux
logsource: linux / process_creation
tactics: []
techniques:
  - T1222.002
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-09-15'
falsepositives:
  - Administrator interacting with immutable files (e.g. for instance backups).
references:
  - https://www.trendmicro.com/en_us/research/22/i/how-malicious-actors-abuse-native-linux-tools-in-their-attacks.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_chattr_immutable_removal.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Remove Immutable File Attribute
id: 34979410-e4b5-4e5d-8cfb-389fdff05c12
related:
    - id: a5b977d6-8a81-4475-91b9-49dbfcd941f7
      type: derived
status: test
description: Detects usage of the 'chattr' utility to remove immutable file attribute.
references:
    - https://www.trendmicro.com/en_us/research/22/i/how-malicious-actors-abuse-native-linux-tools-in-their-attacks.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-15
tags:
    - attack.defense-impairment
    - attack.t1222.002
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith: '/chattr'
        CommandLine|contains: ' -i '
    condition: selection
falsepositives:
    - Administrator interacting with immutable files (e.g. for instance backups).
level: medium
```
