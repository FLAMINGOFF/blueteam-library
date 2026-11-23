---
title: User Has Been Deleted Via Userdel
summary: Detects execution of the "userdel" binary. Which is used to delete a user account and related files. This is sometimes abused by threat actors in order to cover their tracks
sigma_id: 08f26069-6f80-474b-8d1f-d971c6fedea0
status: test
level: medium
platform: linux
logsource: linux / process_creation
tactics:
  - TA0040
techniques:
  - T1531
author: Tuan Le (NCSGroup)
date: '2022-12-26'
falsepositives:
  - Legitimate administrator activities
references:
  - https://linuxize.com/post/how-to-delete-group-in-linux/
  - https://www.cyberciti.biz/faq/linux-remove-user-command/
  - https://www.cybrary.it/blog/0p3n/linux-commands-used-attackers/
  - https://linux.die.net/man/8/userdel
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_userdel.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: User Has Been Deleted Via Userdel
id: 08f26069-6f80-474b-8d1f-d971c6fedea0
status: test
description: Detects execution of the "userdel" binary. Which is used to delete a user account and related files. This is sometimes abused by threat actors in order to cover their tracks
references:
    - https://linuxize.com/post/how-to-delete-group-in-linux/
    - https://www.cyberciti.biz/faq/linux-remove-user-command/
    - https://www.cybrary.it/blog/0p3n/linux-commands-used-attackers/
    - https://linux.die.net/man/8/userdel
author: Tuan Le (NCSGroup)
date: 2022-12-26
tags:
    - attack.impact
    - attack.t1531
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith: '/userdel'
    condition: selection
falsepositives:
    - Legitimate administrator activities
level: medium
```
