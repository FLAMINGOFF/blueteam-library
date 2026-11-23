---
title: Print History File Contents
summary: Detects events in which someone prints the contents of history files to the commandline or redirects it to a file for reconnaissance
sigma_id: d7821ff1-4527-4e33-9f84-d0d57fa2fb66
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
modified: '2022-09-15'
falsepositives:
  - Legitimate administration activities
references:
  - https://github.com/sleventyeleven/linuxprivchecker/
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1552.003/T1552.003.md
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_susp_history_recon.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Print History File Contents
id: d7821ff1-4527-4e33-9f84-d0d57fa2fb66
status: test
description: Detects events in which someone prints the contents of history files to the commandline or redirects it to a file for reconnaissance
references:
    - https://github.com/sleventyeleven/linuxprivchecker/
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1552.003/T1552.003.md
author: Florian Roth (Nextron Systems)
date: 2022-06-20
modified: 2022-09-15
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
            - '/head'
            - '/tail'
            - '/more'
    selection_history:
        - CommandLine|contains:
              - '/.bash_history'
              - '/.zsh_history'
        - CommandLine|endswith:
              - '_history'
              - '.history'
              - 'zhistory'
    condition: all of selection*
falsepositives:
    - Legitimate administration activities
level: medium
```
