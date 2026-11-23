---
title: HackTool - Bloodhound/Sharphound Execution
summary: Detects command line parameters used by Bloodhound and Sharphound hack tools
sigma_id: f376c8a7-a2d0-4ddc-aa0c-16c17236d962
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0007
  - TA0002
techniques:
  - T1087.001
  - T1087.002
  - T1482
  - T1069.001
  - T1069.002
  - T1059.001
author: Florian Roth (Nextron Systems)
date: '2019-12-20'
modified: '2023-02-04'
falsepositives:
  - Other programs that use these command line option and accepts an 'All' parameter
references:
  - https://github.com/BloodHoundAD/BloodHound
  - https://github.com/BloodHoundAD/SharpHound
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_hktl_bloodhound_sharphound.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: HackTool - Bloodhound/Sharphound Execution
id: f376c8a7-a2d0-4ddc-aa0c-16c17236d962
status: test
description: Detects command line parameters used by Bloodhound and Sharphound hack tools
references:
    - https://github.com/BloodHoundAD/BloodHound
    - https://github.com/BloodHoundAD/SharpHound
author: Florian Roth (Nextron Systems)
date: 2019-12-20
modified: 2023-02-04
tags:
    - attack.discovery
    - attack.t1087.001
    - attack.t1087.002
    - attack.t1482
    - attack.t1069.001
    - attack.t1069.002
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Product|contains: 'SharpHound'
        - Description|contains: 'SharpHound'
        - Company|contains:
              - 'SpecterOps'
              - 'evil corp'
        - Image|contains:
              - '\Bloodhound.exe'
              - '\SharpHound.exe'
    selection_cli_1:
        CommandLine|contains:
            - ' -CollectionMethod All '
            - ' --CollectionMethods Session '
            - ' --Loop --Loopduration '
            - ' --PortScanTimeout '
            - '.exe -c All -d '
            - 'Invoke-Bloodhound'
            - 'Get-BloodHoundData'
    selection_cli_2:
        CommandLine|contains|all:
            - ' -JsonFolder '
            - ' -ZipFileName '
    selection_cli_3:
        CommandLine|contains|all:
            - ' DCOnly '
            - ' --NoSaveCache '
    condition: 1 of selection_*
falsepositives:
    - Other programs that use these command line option and accepts an 'All' parameter
level: high
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_hktl_bloodhound_sharphound/info.yml
```
