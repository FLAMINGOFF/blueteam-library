---
title: Potential Perl Reverse Shell Execution
summary: Detects execution of the perl binary with the "-e" flag and common strings related to potential reverse shell activity
sigma_id: 259df6bc-003f-4306-9f54-4ff1a08fa38e
status: test
level: high
platform: linux
logsource: linux / process_creation
tactics:
  - TA0002
techniques: []
author: '@d4ns4n_, Nasreddine Bencherchali (Nextron Systems)'
date: '2023-04-07'
falsepositives:
  - Unlikely
references:
  - https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
  - https://www.revshells.com/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_perl_reverse_shell.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential Perl Reverse Shell Execution
id: 259df6bc-003f-4306-9f54-4ff1a08fa38e
status: test
description: Detects execution of the perl binary with the "-e" flag and common strings related to potential reverse shell activity
references:
    - https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
    - https://www.revshells.com/
author: '@d4ns4n_, Nasreddine Bencherchali (Nextron Systems)'
date: 2023-04-07
tags:
    - attack.execution
logsource:
    category: process_creation
    product: linux
detection:
    selection_img:
        Image|endswith: '/perl'
        CommandLine|contains: ' -e '
    selection_content:
        - CommandLine|contains|all:
              - 'fdopen('
              - '::Socket::INET'
        - CommandLine|contains|all:
              - 'Socket'
              - 'connect'
              - 'open'
              - 'exec'
    condition: all of selection_*
falsepositives:
    - Unlikely
level: high
```
