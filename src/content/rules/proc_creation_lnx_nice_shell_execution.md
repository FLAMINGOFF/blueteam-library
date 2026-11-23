---
title: Shell Execution via Nice - Linux
summary: Detects the use of the "nice" utility to execute a shell. Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.
sigma_id: 093d68c7-762a-42f4-9f46-95e79142571a
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
  - https://gtfobins.github.io/gtfobins/nice/#shell
  - https://github.com/elastic/detection-rules/blob/0aacc5e19292f764a002ea2093b2a076db35b589/rules/_deprecated/execution_shell_evasion_linux_binary.toml
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_nice_shell_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Shell Execution via Nice - Linux
id: 093d68c7-762a-42f4-9f46-95e79142571a
status: test
description: |
    Detects the use of the "nice" utility to execute a shell. Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.
references:
    - https://gtfobins.github.io/gtfobins/nice/#shell
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
    selection:
        Image|endswith: '/nice'
        CommandLine|endswith:
            - '/bin/bash'
            - '/bin/dash'
            - '/bin/fish'
            - '/bin/sh'
            - '/bin/zsh'
    condition: selection
falsepositives:
    - Unknown
level: high
```
