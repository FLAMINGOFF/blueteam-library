---
title: DumpMinitool Execution
summary: Detects the use of "DumpMinitool.exe" a tool that allows the dump of process memory via the use of the "MiniDumpWriteDump"
sigma_id: dee0a7a3-f200-4112-a99b-952196d81e42
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
  - TA0006
techniques:
  - T1036
  - T1003.001
author: Nasreddine Bencherchali (Nextron Systems), Florian Roth (Nextron Systems)
date: '2022-04-06'
modified: '2023-04-12'
falsepositives:
  - Unknown
references:
  - https://twitter.com/mrd0x/status/1511415432888131586
  - https://twitter.com/mrd0x/status/1511489821247684615
  - https://lolbas-project.github.io/lolbas/OtherMSBinaries/DumpMinitool/
  - https://gist.github.com/nasbench/6d58c3c125e2fa1b8f7a09754c1b087f
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_dumpminitool_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: DumpMinitool Execution
id: dee0a7a3-f200-4112-a99b-952196d81e42
status: test
description: Detects the use of "DumpMinitool.exe" a tool that allows the dump of process memory via the use of the "MiniDumpWriteDump"
references:
    - https://twitter.com/mrd0x/status/1511415432888131586
    - https://twitter.com/mrd0x/status/1511489821247684615
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/DumpMinitool/
    - https://gist.github.com/nasbench/6d58c3c125e2fa1b8f7a09754c1b087f
author: Nasreddine Bencherchali (Nextron Systems), Florian Roth (Nextron Systems)
date: 2022-04-06
modified: 2023-04-12
tags:
    - attack.stealth
    - attack.t1036
    - attack.t1003.001
    - attack.credential-access
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith:
              - '\DumpMinitool.exe'
              - '\DumpMinitool.x86.exe'
              - '\DumpMinitool.arm64.exe'
        - OriginalFileName:
              - 'DumpMinitool.exe'
              - 'DumpMinitool.x86.exe'
              - 'DumpMinitool.arm64.exe'
    selection_cli:
        CommandLine|contains:
            - ' Full'
            - ' Mini'
            - ' WithHeap'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```
