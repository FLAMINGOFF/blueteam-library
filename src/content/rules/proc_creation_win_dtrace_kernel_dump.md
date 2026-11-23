---
title: Suspicious Kernel Dump Using Dtrace
summary: Detects suspicious way to dump the kernel on Windows systems using dtrace.exe, which is available on Windows systems since Windows 10 19H1
sigma_id: 7124aebe-4cd7-4ccb-8df0-6d6b93c96795
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0007
techniques:
  - T1082
author: Florian Roth (Nextron Systems)
date: '2021-12-28'
falsepositives:
  - Unknown
references:
  - https://twitter.com/0gtweet/status/1474899714290208777?s=12
  - https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/dtrace
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_dtrace_kernel_dump.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Kernel Dump Using Dtrace
id: 7124aebe-4cd7-4ccb-8df0-6d6b93c96795
status: test
description: Detects suspicious way to dump the kernel on Windows systems using dtrace.exe, which is available on Windows systems since Windows 10 19H1
references:
    - https://twitter.com/0gtweet/status/1474899714290208777?s=12
    - https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/dtrace
author: Florian Roth (Nextron Systems)
date: 2021-12-28
tags:
    - attack.discovery
    - attack.t1082
logsource:
    product: windows
    category: process_creation
detection:
    selection_plain:
        Image|endswith: '\dtrace.exe'
        CommandLine|contains: 'lkd(0)'
    selection_obfuscated:
        CommandLine|contains|all:
            - 'syscall:::return'
            - 'lkd('
    condition: 1 of selection*
falsepositives:
    - Unknown
level: high
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_dtrace_kernel_dump/info.yml
```
