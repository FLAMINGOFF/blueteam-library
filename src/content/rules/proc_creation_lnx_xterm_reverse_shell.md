---
title: Potential Xterm Reverse Shell
summary: Detects usage of "xterm" as a potential reverse shell tunnel
sigma_id: 4e25af4b-246d-44ea-8563-e42aacab006b
status: test
level: medium
platform: linux
logsource: linux / process_creation
tactics:
  - TA0002
techniques:
  - T1059
author: '@d4ns4n_'
date: '2023-04-24'
falsepositives:
  - Unknown
references:
  - https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
  - https://www.revshells.com/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_xterm_reverse_shell.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential Xterm Reverse Shell
id: 4e25af4b-246d-44ea-8563-e42aacab006b
status: test
description: Detects usage of "xterm" as a potential reverse shell tunnel
references:
    - https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
    - https://www.revshells.com/
author: '@d4ns4n_'
date: 2023-04-24
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|contains: 'xterm'
        CommandLine|contains: '-display'
        CommandLine|endswith: ':1'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
