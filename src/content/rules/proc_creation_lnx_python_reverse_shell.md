---
title: Python Reverse Shell Execution Via PTY And Socket Modules
summary: Detects the execution of python with calls to the socket and pty module in order to connect and spawn a potential reverse shell.
sigma_id: 32e62bc7-3de0-4bb1-90af-532978fe42c0
status: test
level: high
platform: linux
logsource: linux / process_creation
tactics:
  - TA0002
techniques: []
author: '@d4ns4n_, Nasreddine Bencherchali (Nextron Systems)'
date: '2023-04-24'
modified: '2024-11-04'
falsepositives:
  - Unknown
references:
  - https://www.revshells.com/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_python_reverse_shell.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Python Reverse Shell Execution Via PTY And Socket Modules
id: 32e62bc7-3de0-4bb1-90af-532978fe42c0
related:
    - id: c4042d54-110d-45dd-a0e1-05c47822c937
      type: similar
status: test
description: |
    Detects the execution of python with calls to the socket and pty module in order to connect and spawn a potential reverse shell.
references:
    - https://www.revshells.com/
author: '@d4ns4n_, Nasreddine Bencherchali (Nextron Systems)'
date: 2023-04-24
modified: 2024-11-04
tags:
    - attack.execution
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|contains: 'python'
        CommandLine|contains|all:
            - ' -c '
            - 'import'
            - 'pty'
            - 'socket'
            - 'spawn'
            - '.connect'
    condition: selection
falsepositives:
    - Unknown
level: high
```
