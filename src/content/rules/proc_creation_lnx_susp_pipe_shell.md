---
title: Linux Shell Pipe to Shell
summary: Detects suspicious process command line that starts with a shell that executes something and finally gets piped into another shell
sigma_id: 880973f3-9708-491c-a77b-2a35a1921158
status: test
level: medium
platform: linux
logsource: linux / process_creation
tactics: []
techniques:
  - T1140
author: Florian Roth (Nextron Systems)
date: '2022-03-14'
modified: '2022-07-26'
falsepositives:
  - Legitimate software that uses these patterns
references:
  - Internal Research
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Linux Shell Pipe to Shell
id: 880973f3-9708-491c-a77b-2a35a1921158
status: test
description: Detects suspicious process command line that starts with a shell that executes something and finally gets piped into another shell
references:
    - Internal Research
author: Florian Roth (Nextron Systems)
date: 2022-03-14
modified: 2022-07-26
tags:
    - attack.stealth
    - attack.t1140
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        CommandLine|startswith:
            - 'sh -c '
            - 'bash -c '
    selection_exec:
        - CommandLine|contains:
              - '| bash '
              - '| sh '
              - '|bash '
              - '|sh '
        - CommandLine|endswith:
              - '| bash'
              - '| sh'
              - '|bash'
              - ' |sh'
    condition: all of selection*
falsepositives:
    - Legitimate software that uses these patterns
level: medium
```
