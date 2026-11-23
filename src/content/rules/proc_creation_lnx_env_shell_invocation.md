---
title: Shell Invocation via Env Command - Linux
summary: Detects the use of the env command to invoke a shell. This may indicate an attempt to bypass restricted environments, escalate privileges, or execute arbitrary commands.
sigma_id: bed978f8-7f3a-432b-82c5-9286a9b3031a
status: test
level: high
platform: linux
logsource: linux / process_creation
tactics:
  - TA0002
techniques:
  - T1059.004
author: Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.)
date: '2024-09-02'
modified: '2026-01-08'
falsepositives:
  - Github operations such as ghe-backup
references:
  - https://gtfobins.github.io/gtfobins/env/#shell
  - https://github.com/elastic/detection-rules/blob/0aacc5e19292f764a002ea2093b2a076db35b589/rules/_deprecated/execution_shell_evasion_linux_binary.toml
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_env_shell_invocation.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Shell Invocation via Env Command - Linux
id: bed978f8-7f3a-432b-82c5-9286a9b3031a
status: test
description: |
    Detects the use of the env command to invoke a shell. This may indicate an attempt to bypass restricted environments, escalate privileges, or execute arbitrary commands.
references:
    - https://gtfobins.github.io/gtfobins/env/#shell
    - https://github.com/elastic/detection-rules/blob/0aacc5e19292f764a002ea2093b2a076db35b589/rules/_deprecated/execution_shell_evasion_linux_binary.toml
author: Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.)
date: 2024-09-02
modified: 2026-01-08
tags:
    - attack.execution
    - attack.t1059.004
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/env'
        CommandLine|contains:
            - '/bin/bash'
            - '/bin/dash'
            - '/bin/fish'
            - '/bin/sh'
            - '/bin/zsh'
    condition: selection
falsepositives:
    - Github operations such as ghe-backup
level: high
```
