---
title: Potential Adplus.EXE Abuse
summary: Detects execution of "AdPlus.exe", a binary that is part of the Windows SDK that can be used as a LOLBIN in order to dump process memory and execute arbitrary commands.
sigma_id: 2f869d59-7f6a-4931-992c-cce556ff2d53
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
  - TA0006
techniques:
  - T1003.001
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-06-09'
modified: '2023-06-23'
falsepositives:
  - Legitimate usage of Adplus for debugging purposes
references:
  - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Adplus/
  - https://twitter.com/nas_bench/status/1534916659676422152
  - https://twitter.com/nas_bench/status/1534915321856917506
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_adplus_memory_dump.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential Adplus.EXE Abuse
id: 2f869d59-7f6a-4931-992c-cce556ff2d53
status: test
description: Detects execution of "AdPlus.exe", a binary that is part of the Windows SDK that can be used as a LOLBIN in order to dump process memory and execute arbitrary commands.
references:
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Adplus/
    - https://twitter.com/nas_bench/status/1534916659676422152
    - https://twitter.com/nas_bench/status/1534915321856917506
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-06-09
modified: 2023-06-23
tags:
    - attack.execution
    - attack.credential-access
    - attack.t1003.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\adplus.exe'
        - OriginalFileName: 'Adplus.exe'
    selection_cli:
        CommandLine|contains:
            # Dump process memory
            - ' -hang '
            - ' -pn '
            - ' -pmn '
            - ' -p '
            - ' -po '
            # Using a config file
            - ' -c '
            # Execute commands inline
            - ' -sc '
    condition: all of selection_*
falsepositives:
    - Legitimate usage of Adplus for debugging purposes
level: high
```
