---
title: Potential Persistence Via VMwareToolBoxCmd.EXE VM State Change Script
summary: Detects execution of the "VMwareToolBoxCmd.exe" with the "script" and "set" flag to setup a specific script to run for a specific VM state
sigma_id: 7aa4e81a-a65c-4e10-9f81-b200eb229d7d
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
  - TA0003
techniques:
  - T1059
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-06-14'
falsepositives:
  - Unknown
references:
  - https://bohops.com/2021/10/08/analyzing-and-detecting-a-vmtools-persistence-technique/
  - https://www.hexacorn.com/blog/2017/01/14/beyond-good-ol-run-key-part-53/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_vmware_toolbox_cmd_persistence.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential Persistence Via VMwareToolBoxCmd.EXE VM State Change Script
id: 7aa4e81a-a65c-4e10-9f81-b200eb229d7d
related:
    - id: 236d8e89-ed95-4789-a982-36f4643738ba
      type: derived
status: test
description: Detects execution of the "VMwareToolBoxCmd.exe" with the "script" and "set" flag to setup a specific script to run for a specific VM state
references:
    - https://bohops.com/2021/10/08/analyzing-and-detecting-a-vmtools-persistence-technique/
    - https://www.hexacorn.com/blog/2017/01/14/beyond-good-ol-run-key-part-53/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-06-14
tags:
    - attack.execution
    - attack.persistence
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\VMwareToolBoxCmd.exe'
        - OriginalFileName: 'toolbox-cmd.exe'
    selection_cli:
        CommandLine|contains|all:
            - ' script '
            - ' set '
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```
