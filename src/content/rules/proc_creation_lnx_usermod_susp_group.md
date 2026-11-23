---
title: User Added To Root/Sudoers Group Using Usermod
summary: Detects usage of the "usermod" binary to add users add users to the root or suoders groups
sigma_id: 6a50f16c-3b7b-42d1-b081-0fdd3ba70a73
status: test
level: medium
platform: linux
logsource: linux / process_creation
tactics:
  - TA0004
  - TA0003
techniques: []
author: TuanLe (GTSC)
date: '2022-12-21'
falsepositives:
  - Legitimate administrator activities
references:
  - https://pberba.github.io/security/2021/11/23/linux-threat-hunting-for-persistence-account-creation-manipulation/
  - https://www.configserverfirewall.com/ubuntu-linux/ubuntu-add-user-to-root-group/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_usermod_susp_group.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: User Added To Root/Sudoers Group Using Usermod
id: 6a50f16c-3b7b-42d1-b081-0fdd3ba70a73
status: test
description: Detects usage of the "usermod" binary to add users add users to the root or suoders groups
references:
    - https://pberba.github.io/security/2021/11/23/linux-threat-hunting-for-persistence-account-creation-manipulation/
    - https://www.configserverfirewall.com/ubuntu-linux/ubuntu-add-user-to-root-group/
author: TuanLe (GTSC)
date: 2022-12-21
tags:
    - attack.privilege-escalation
    - attack.persistence
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith: '/usermod'
        CommandLine|contains:
            - '-aG root'
            - '-aG sudoers'
    condition: selection
falsepositives:
    - Legitimate administrator activities
level: medium
```
