---
title: Shell Execution via Git - Linux
summary: Detects the use of the "git" utility to execute a shell. Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.
sigma_id: 47b3bbd4-1bf7-48cc-84ab-995362aaa75a
status: test
level: high
platform: linux
logsource: linux / process_creation
tactics:
  - TA0002
techniques:
  - T1059
author: Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.)
date: '2024-09-02'
falsepositives:
  - Unknown
references:
  - https://gtfobins.github.io/gtfobins/git/#shell
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_git_shell_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Shell Execution via Git - Linux
id: 47b3bbd4-1bf7-48cc-84ab-995362aaa75a
status: test
description: |
    Detects the use of the "git" utility to execute a shell. Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.
references:
    - https://gtfobins.github.io/gtfobins/git/#shell
author: Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.)
date: 2024-09-02
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        ParentImage|endswith: '/git'
        ParentCommandLine|contains|all:
            - ' -p '
            - 'help'
        CommandLine|contains:
            - 'bash 0<&1'
            - 'dash 0<&1'
            - 'sh 0<&1'
    condition: selection
falsepositives:
    - Unknown
level: high
```
