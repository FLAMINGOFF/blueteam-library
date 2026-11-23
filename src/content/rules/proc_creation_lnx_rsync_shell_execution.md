---
title: Shell Execution via Rsync - Linux
summary: Detects the use of the "rsync" utility to execute a shell. Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.
sigma_id: e2326866-609f-4015-aea9-7ec634e8aa04
status: experimental
level: high
platform: linux
logsource: linux / process_creation
tactics:
  - TA0002
techniques:
  - T1059
author: Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.), Florian Roth
date: '2024-09-02'
modified: '2025-01-18'
falsepositives:
  - Legitimate cases in which "rsync" is used to execute a shell
references:
  - https://gtfobins.github.io/gtfobins/rsync/#shell
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_rsync_shell_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Shell Execution via Rsync - Linux
id: e2326866-609f-4015-aea9-7ec634e8aa04
status: experimental
description: |
    Detects the use of the "rsync" utility to execute a shell. Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.
references:
    - https://gtfobins.github.io/gtfobins/rsync/#shell
author: Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.), Florian Roth
date: 2024-09-02
modified: 2025-01-18
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: linux
detection:
    selection_img:
        Image|endswith:
            - '/rsync'
            - '/rsyncd'
        CommandLine|contains: ' -e '
    selection_cli:
        CommandLine|contains:
            - '/ash '
            - '/bash '
            - '/dash '
            - '/csh '
            - '/sh '
            - '/zsh '
            - '/tcsh '
            - '/ksh '
            - "'ash "
            - "'bash "
            - "'dash "
            - "'csh "
            - "'sh "
            - "'zsh "
            - "'tcsh "
            - "'ksh "
    condition: all of selection_*
falsepositives:
    - Legitimate cases in which "rsync" is used to execute a shell
level: high
```
