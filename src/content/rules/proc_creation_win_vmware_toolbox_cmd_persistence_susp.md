---
title: Suspicious Persistence Via VMwareToolBoxCmd.EXE VM State Change Script
summary: Detects execution of the "VMwareToolBoxCmd.exe" with the "script" and "set" flag to setup a specific script that's located in a potentially suspicious location to run for a specific VM state
sigma_id: 236d8e89-ed95-4789-a982-36f4643738ba
status: test
level: high
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
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_vmware_toolbox_cmd_persistence_susp.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Persistence Via VMwareToolBoxCmd.EXE VM State Change Script
id: 236d8e89-ed95-4789-a982-36f4643738ba
related:
    - id: 7aa4e81a-a65c-4e10-9f81-b200eb229d7d
      type: derived
status: test
description: Detects execution of the "VMwareToolBoxCmd.exe" with the "script" and "set" flag to setup a specific script that's located in a potentially suspicious location to run for a specific VM state
references:
    - https://bohops.com/2021/10/08/analyzing-and-detecting-a-vmtools-persistence-technique/
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
    selection_bin_img:
        - Image|endswith: '\VMwareToolBoxCmd.exe'
        - OriginalFileName: 'toolbox-cmd.exe'
    selection_bin_cli:
        CommandLine|contains|all:
            - ' script '
            - ' set '
    selection_susp_paths:
        CommandLine|contains:
            - ':\PerfLogs\'
            - ':\Temp\'
            - ':\Windows\System32\Tasks\'
            - ':\Windows\Tasks\'
            - ':\Windows\Temp\'
            - '\AppData\Local\Temp'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
