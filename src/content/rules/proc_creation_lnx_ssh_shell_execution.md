---
title: Shell Invocation Via Ssh - Linux
summary: Detects the use of the "ssh" utility to execute a shell. Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.
sigma_id: 8737b7f6-8df3-4bb7-b1da-06019b99b687
status: test
level: high
platform: linux
logsource: linux / process_creation
tactics:
  - TA0002
techniques:
  - T1059
author: Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.)
date: '2024-08-29'
falsepositives:
  - Unknown
references:
  - https://gtfobins.github.io/gtfobins/ssh/
  - https://github.com/elastic/detection-rules/blob/0aacc5e19292f764a002ea2093b2a076db35b589/rules/_deprecated/execution_shell_evasion_linux_binary.toml
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_ssh_shell_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Shell Invocation Via Ssh - Linux
id: 8737b7f6-8df3-4bb7-b1da-06019b99b687
status: test
description: |
    Detects the use of the "ssh" utility to execute a shell. Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.
references:
    - https://gtfobins.github.io/gtfobins/ssh/
    - https://github.com/elastic/detection-rules/blob/0aacc5e19292f764a002ea2093b2a076db35b589/rules/_deprecated/execution_shell_evasion_linux_binary.toml
author: Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.)
date: 2024-08-29
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: linux
detection:
    selection_img:
        Image|endswith: '/ssh'
        CommandLine|contains:
            - 'ProxyCommand=;'
            - 'permitlocalcommand=yes'
            - 'localhost'
    selection_cli:
        CommandLine|contains:
            - '/bin/bash'
            - '/bin/dash'
            - '/bin/fish'
            - '/bin/sh'
            - '/bin/zsh'
            - 'sh 0<&2 1>&2'
            - 'sh 1>&2 0<&2'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
