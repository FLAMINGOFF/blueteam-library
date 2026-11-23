---
title: Group Has Been Deleted Via Groupdel
summary: Detects execution of the "groupdel" binary. Which is used to delete a group. This is sometimes abused by threat actors in order to cover their tracks
sigma_id: 8a46f16c-8c4c-82d1-b121-0fdd3ba70a84
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
  - https://linux.die.net/man/8/groupdel
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_groupdel.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Group Has Been Deleted Via Groupdel
id: 8a46f16c-8c4c-82d1-b121-0fdd3ba70a84
status: test
description: Detects execution of the "groupdel" binary. Which is used to delete a group. This is sometimes abused by threat actors in order to cover their tracks
references:
    - https://linuxize.com/post/how-to-delete-group-in-linux/
    - https://www.cyberciti.biz/faq/linux-remove-user-command/
    - https://www.cybrary.it/blog/0p3n/linux-commands-used-attackers/
    - https://linux.die.net/man/8/groupdel
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
        Image|endswith: '/groupdel'
    condition: selection
falsepositives:
    - Legitimate administrator activities
level: medium
```
