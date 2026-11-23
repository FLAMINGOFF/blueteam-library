---
title: HackTool - LocalPotato Execution
summary: Detects the execution of the LocalPotato POC based on basic PE metadata information and default CLI examples
sigma_id: 6bd75993-9888-4f91-9404-e1e4e4e34b77
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
  - TA0005
techniques: []
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-02-14'
modified: '2024-11-23'
falsepositives:
  - Unlikely
references:
  - https://www.localpotato.com/localpotato_html/LocalPotato.html
  - https://github.com/decoder-it/LocalPotato
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_hktl_localpotato.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: HackTool - LocalPotato Execution
id: 6bd75993-9888-4f91-9404-e1e4e4e34b77
status: test
description: Detects the execution of the LocalPotato POC based on basic PE metadata information and default CLI examples
references:
    - https://www.localpotato.com/localpotato_html/LocalPotato.html
    - https://github.com/decoder-it/LocalPotato
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-02-14
modified: 2024-11-23
tags:
    - attack.privilege-escalation
    - cve.2023-21746
    - attack.stealth
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith: '\LocalPotato.exe'
    selection_cli:
        CommandLine|contains|all:
            - '.exe -i C:\'
            - '-o Windows\'
    selection_hash_plain:
        Hashes|contains:
            - 'IMPHASH=E1742EE971D6549E8D4D81115F88F1FC'
            - 'IMPHASH=DD82066EFBA94D7556EF582F247C8BB5'
    condition: 1 of selection_*
falsepositives:
    - Unlikely
level: high
```
