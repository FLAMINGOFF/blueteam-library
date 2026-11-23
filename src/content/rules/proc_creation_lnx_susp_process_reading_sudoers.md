---
title: Access of Sudoers File Content
summary: Detects the execution of a text-based file access or inspection utilities to read the content of /etc/sudoers in order to potentially list all users that have sudo rights.
sigma_id: 0f79c4d2-4e1f-4683-9c36-b5469a665e06
status: test
level: medium
platform: linux
logsource: linux / process_creation
tactics:
  - TA0043
techniques:
  - T1592.004
author: Florian Roth (Nextron Systems)
date: '2022-06-20'
modified: '2025-06-04'
falsepositives:
  - Legitimate administration activities
references:
  - https://github.com/sleventyeleven/linuxprivchecker/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_susp_process_reading_sudoers.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Access of Sudoers File Content
id: 0f79c4d2-4e1f-4683-9c36-b5469a665e06
status: test
description: Detects the execution of a text-based file access or inspection utilities to read the content of /etc/sudoers in order to potentially list all users that have sudo rights.
references:
    - https://github.com/sleventyeleven/linuxprivchecker/
author: Florian Roth (Nextron Systems)
date: 2022-06-20
modified: 2025-06-04
tags:
    - attack.reconnaissance
    - attack.t1592.004
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith:
            - '/cat'
            - '/ed'
            - '/egrep'
            - '/emacs'
            - '/fgrep'
            - '/grep'
            - '/head'
            - '/less'
            - '/more'
            - '/nano'
            - '/tail'
        CommandLine|contains: ' /etc/sudoers'
    condition: selection
falsepositives:
    - Legitimate administration activities
level: medium
```
