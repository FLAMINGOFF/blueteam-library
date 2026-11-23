---
title: Suspicious Windows Update Agent Empty Cmdline
summary: Detects suspicious Windows Update Agent activity in which a wuauclt.exe process command line doesn't contain any command line flags
sigma_id: 52d097e2-063e-4c9c-8fbb-855c8948d135
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques:
  - T1036
author: Florian Roth (Nextron Systems)
date: '2022-02-26'
modified: '2023-11-11'
falsepositives:
  - Unknown
references:
  - https://redcanary.com/blog/blackbyte-ransomware/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_wuauclt_no_cli_flags_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Windows Update Agent Empty Cmdline
id: 52d097e2-063e-4c9c-8fbb-855c8948d135
status: test
description: |
    Detects suspicious Windows Update Agent activity in which a wuauclt.exe process command line doesn't contain any command line flags
references:
    - https://redcanary.com/blog/blackbyte-ransomware/
author: Florian Roth (Nextron Systems)
date: 2022-02-26
modified: 2023-11-11
tags:
    - attack.stealth
    - attack.t1036
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\Wuauclt.exe'
        - OriginalFileName: 'Wuauclt.exe'
    selection_cli:
        CommandLine|endswith:
            - 'Wuauclt'
            - 'Wuauclt.exe'
    condition: all of selection*
falsepositives:
    - Unknown
level: high
```
