---
title: Renamed NirCmd.EXE Execution
summary: Detects the execution of a renamed "NirCmd.exe" binary based on the PE metadata fields.
sigma_id: 264982dc-dbad-4dce-b707-1e0d3e0f73d9
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
  - TA0005
techniques:
  - T1059
  - T1202
author: X__Junior (Nextron Systems)
date: '2024-03-11'
falsepositives:
  - Unknown
references:
  - https://www.microsoft.com/en-us/security/blog/2024/01/17/new-ttps-observed-in-mint-sandstorm-campaign-targeting-high-profile-individuals-at-universities-and-research-orgs/
  - https://www.nirsoft.net/utils/nircmd.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_renamed_nircmd.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Renamed NirCmd.EXE Execution
id: 264982dc-dbad-4dce-b707-1e0d3e0f73d9
status: test
description: Detects the execution of a renamed "NirCmd.exe" binary based on the PE metadata fields.
references:
    - https://www.microsoft.com/en-us/security/blog/2024/01/17/new-ttps-observed-in-mint-sandstorm-campaign-targeting-high-profile-individuals-at-universities-and-research-orgs/
    - https://www.nirsoft.net/utils/nircmd.html
author: X__Junior (Nextron Systems)
date: 2024-03-11
tags:
    - attack.execution
    - attack.stealth
    - attack.t1059
    - attack.t1202
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        OriginalFileName: 'NirCmd.exe'
    filter_main_img:
        Image|endswith:
            - '\nircmd.exe'
            - '\nircmdc.exe'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: high
```
