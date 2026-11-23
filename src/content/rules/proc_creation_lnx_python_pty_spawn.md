---
title: Python Spawning Pretty TTY Via PTY Module
summary: Detects a python process calling to the PTY module in order to spawn a pretty tty which could be indicative of potential reverse shell activity.
sigma_id: c4042d54-110d-45dd-a0e1-05c47822c937
status: test
level: medium
platform: linux
logsource: linux / process_creation
tactics:
  - TA0002
techniques:
  - T1059
author: Nextron Systems
date: '2022-06-03'
modified: '2024-11-04'
falsepositives:
  - Unknown
references:
  - https://www.volexity.com/blog/2022/06/02/zero-day-exploitation-of-atlassian-confluence/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_python_pty_spawn.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Python Spawning Pretty TTY Via PTY Module
id: c4042d54-110d-45dd-a0e1-05c47822c937
related:
    - id: 32e62bc7-3de0-4bb1-90af-532978fe42c0
      type: similar
status: test
description: |
    Detects a python process calling to the PTY module in order to spawn a pretty tty which could be indicative of potential reverse shell activity.
references:
    - https://www.volexity.com/blog/2022/06/02/zero-day-exploitation-of-atlassian-confluence/
author: Nextron Systems
date: 2022-06-03
modified: 2024-11-04
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: linux
detection:
    selection_img:
        - Image|endswith:
              - '/python'
              - '/python2'
              - '/python3'
        - Image|contains:
              - '/python2.'  # python image is always of the form ../python3.10; ../python is just a symlink
              - '/python3.'
    selection_cli_import:
        CommandLine|contains:
            - 'import pty'
            - 'from pty '
    selection_cli_spawn:
        CommandLine|contains: 'spawn'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```
