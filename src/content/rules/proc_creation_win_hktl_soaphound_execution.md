---
title: HackTool - SOAPHound Execution
summary: Detects the execution of SOAPHound, a .NET tool for collecting Active Directory data, using specific command-line arguments that may indicate an attempt to extract sensitive AD information.
sigma_id: e92a4287-e072-4a40-9739-370c106bb750
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0007
techniques:
  - T1087
author: '@kostastsale'
date: '2024-01-26'
falsepositives:
  - Unknown
references:
  - https://github.com/FalconForceTeam/SOAPHound
  - https://medium.com/falconforce/soaphound-tool-to-collect-active-directory-data-via-adws-165aca78288c
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_hktl_soaphound_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: HackTool - SOAPHound Execution
id: e92a4287-e072-4a40-9739-370c106bb750
status: test
description: |
    Detects the execution of SOAPHound, a .NET tool for collecting Active Directory data, using specific command-line arguments that may indicate an attempt to extract sensitive AD information.
references:
    - https://github.com/FalconForceTeam/SOAPHound
    - https://medium.com/falconforce/soaphound-tool-to-collect-active-directory-data-via-adws-165aca78288c
author: '@kostastsale'
date: 2024-01-26
tags:
    - attack.discovery
    - attack.t1087
logsource:
    product: windows
    category: process_creation
detection:
    selection_1:
        CommandLine|contains:
            - ' --buildcache '
            - ' --bhdump '
            - ' --certdump '
            - ' --dnsdump '
    selection_2:
        CommandLine|contains:
            - ' -c '
            - ' --cachefilename '
            - ' -o '
            - ' --outputdirectory'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_hktl_soaphound_execution/info.yml
```
