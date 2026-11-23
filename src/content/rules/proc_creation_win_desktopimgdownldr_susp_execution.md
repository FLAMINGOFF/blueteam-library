---
title: Suspicious Desktopimgdownldr Command
summary: Detects a suspicious Microsoft desktopimgdownldr execution with parameters used to download files from the Internet
sigma_id: bb58aa4a-b80b-415a-a2c0-2f65a4c81009
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0011
techniques:
  - T1105
author: Florian Roth (Nextron Systems)
date: '2020-07-03'
modified: '2021-11-27'
falsepositives:
  - False positives depend on scripts and administrative tools used in the monitored environment
references:
  - https://labs.sentinelone.com/living-off-windows-land-a-new-native-file-downldr/
  - https://twitter.com/SBousseaden/status/1278977301745741825
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_desktopimgdownldr_susp_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Desktopimgdownldr Command
id: bb58aa4a-b80b-415a-a2c0-2f65a4c81009
status: test
description: Detects a suspicious Microsoft desktopimgdownldr execution with parameters used to download files from the Internet
references:
    - https://labs.sentinelone.com/living-off-windows-land-a-new-native-file-downldr/
    - https://twitter.com/SBousseaden/status/1278977301745741825
author: Florian Roth (Nextron Systems)
date: 2020-07-03
modified: 2021-11-27
tags:
    - attack.command-and-control
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine|contains: ' /lockscreenurl:'
    selection1_filter:
        CommandLine|contains:
            - '.jpg'
            - '.jpeg'
            - '.png'
    selection_reg:
        CommandLine|contains|all:
            - 'reg delete'
            - '\PersonalizationCSP'
    condition: ( selection1 and not selection1_filter ) or selection_reg
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: high
```
