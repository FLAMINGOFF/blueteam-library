---
title: Bash Interactive Shell
summary: Detects execution of the bash shell with the interactive flag "-i".
sigma_id: 6104e693-a7d6-4891-86cb-49a258523559
status: test
level: low
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
  - https://linux.die.net/man/1/bash
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Bash Interactive Shell
id: 6104e693-a7d6-4891-86cb-49a258523559
status: test
description: Detects execution of the bash shell with the interactive flag "-i".
references:
    - https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
    - https://www.revshells.com/
    - https://linux.die.net/man/1/bash
author: '@d4ns4n_'
date: 2023-04-07
tags:
    - attack.execution
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/bash'
        CommandLine|contains: ' -i '
    condition: selection
falsepositives:
    - Unknown
level: low
```
