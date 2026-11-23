---
title: Potential Ruby Reverse Shell
summary: Detects execution of ruby with the "-e" flag and calls to "socket" related functions. This could be an indication of a potential attempt to setup a reverse shell
sigma_id: b8bdac18-c06e-4016-ac30-221553e74f59
status: test
level: medium
platform: linux
logsource: linux / process_creation
tactics:
  - TA0002
techniques: []
author: '@d4ns4n_'
date: '2023-04-07'
falsepositives:
  - Unknown
references:
  - https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
  - https://www.revshells.com/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_ruby_reverse_shell.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential Ruby Reverse Shell
id: b8bdac18-c06e-4016-ac30-221553e74f59
status: test
description: Detects execution of ruby with the "-e" flag and calls to "socket" related functions. This could be an indication of a potential attempt to setup a reverse shell
references:
    - https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
    - https://www.revshells.com/
author: '@d4ns4n_'
date: 2023-04-07
tags:
    - attack.execution
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|contains: 'ruby'
        CommandLine|contains|all:
            - ' -e'
            - 'rsocket'
            - 'TCPSocket'
        CommandLine|contains:
            - ' ash'
            - ' bash'
            - ' bsh'
            - ' csh'
            - ' ksh'
            - ' pdksh'
            - ' sh'
            - ' tcsh'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
