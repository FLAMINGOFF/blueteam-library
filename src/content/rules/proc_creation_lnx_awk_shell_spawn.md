---
title: Suspicious Invocation of Shell via AWK - Linux
summary: |-
  Detects the execution of "awk" or it's sibling commands, to invoke a shell using the system() function.
  This behavior is commonly associated with attempts to execute arbitrary commands or escalate privileges, potentially leading to unauthorized access or further exploitation.
sigma_id: 8c1a5675-cb85-452f-a298-b01b22a51856
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
  - https://gtfobins.github.io/gtfobins/awk/#shell
  - https://gtfobins.github.io/gtfobins/gawk/#shell
  - https://gtfobins.github.io/gtfobins/nawk/#shell
  - https://gtfobins.github.io/gtfobins/mawk/#shell
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_awk_shell_spawn.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Invocation of Shell via AWK - Linux
id: 8c1a5675-cb85-452f-a298-b01b22a51856
status: test
description: |
    Detects the execution of "awk" or it's sibling commands, to invoke a shell using the system() function.
    This behavior is commonly associated with attempts to execute arbitrary commands or escalate privileges, potentially leading to unauthorized access or further exploitation.
references:
    - https://gtfobins.github.io/gtfobins/awk/#shell
    - https://gtfobins.github.io/gtfobins/gawk/#shell
    - https://gtfobins.github.io/gtfobins/nawk/#shell
    - https://gtfobins.github.io/gtfobins/mawk/#shell
author: Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.)
date: 2024-09-02
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: linux
detection:
    selection_img:
        Image|endswith:
            - '/awk'
            - '/gawk'
            - '/mawk'
            - '/nawk'
        CommandLine|contains: 'BEGIN {system'
    selection_cli:
        CommandLine|contains:
            - '/bin/bash'
            - '/bin/dash'
            - '/bin/fish'
            - '/bin/sh'
            - '/bin/zsh'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
