---
title: Shell Execution GCC  - Linux
summary: Detects the use of the "gcc" utility to execute a shell. Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.
sigma_id: 9b5de532-a757-4d70-946c-1f3e44f48b4d
status: test
level: high
platform: linux
logsource: linux / process_creation
tactics:
  - TA0007
techniques:
  - T1083
author: Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.)
date: '2024-09-02'
falsepositives:
  - Unknown
references:
  - https://gtfobins.github.io/gtfobins/gcc/#shell
  - https://gtfobins.github.io/gtfobins/c89/#shell
  - https://gtfobins.github.io/gtfobins/c99/#shell
  - https://github.com/elastic/detection-rules/blob/0aacc5e19292f764a002ea2093b2a076db35b589/rules/_deprecated/execution_shell_evasion_linux_binary.toml
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_gcc_shell_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Shell Execution GCC  - Linux
id: 9b5de532-a757-4d70-946c-1f3e44f48b4d
status: test
description: |
    Detects the use of the "gcc" utility to execute a shell. Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.
references:
    - https://gtfobins.github.io/gtfobins/gcc/#shell
    - https://gtfobins.github.io/gtfobins/c89/#shell
    - https://gtfobins.github.io/gtfobins/c99/#shell
    - https://github.com/elastic/detection-rules/blob/0aacc5e19292f764a002ea2093b2a076db35b589/rules/_deprecated/execution_shell_evasion_linux_binary.toml
author: Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.)
date: 2024-09-02
tags:
    - attack.discovery
    - attack.t1083
logsource:
    category: process_creation
    product: linux
detection:
    selection_img:
        Image|endswith:
            - '/c89'
            - '/c99'
            - '/gcc'
        CommandLine|contains: '-wrapper'
    selection_cli:
        CommandLine|contains:
            - '/bin/bash,-s'
            - '/bin/dash,-s'
            - '/bin/fish,-s'
            - '/bin/sh,-s'
            - '/bin/zsh,-s'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
