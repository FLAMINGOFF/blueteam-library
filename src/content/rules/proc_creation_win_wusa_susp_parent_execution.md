---
title: Wusa.EXE Executed By Parent Process Located In Suspicious Location
summary: |-
  Detects execution of the "wusa.exe" (Windows Update Standalone Installer) utility by a parent process that is located in a suspicious location.
  Attackers could instantiate an instance of "wusa.exe" in order to bypass User Account Control (UAC). They can duplicate the access token from "wusa.exe" to gain elevated privileges.
sigma_id: ef64fc9c-a45e-43cc-8fd8-7d75d73b4c99
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques: []
author: X__Junior (Nextron Systems)
date: '2023-11-26'
modified: '2024-08-15'
falsepositives:
  - Unknown
references:
  - https://www.fortinet.com/blog/threat-research/konni-campaign-distributed-via-malicious-document
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_wusa_susp_parent_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Wusa.EXE Executed By Parent Process Located In Suspicious Location
id: ef64fc9c-a45e-43cc-8fd8-7d75d73b4c99
status: test
description: |
    Detects execution of the "wusa.exe" (Windows Update Standalone Installer) utility by a parent process that is located in a suspicious location.
    Attackers could instantiate an instance of "wusa.exe" in order to bypass User Account Control (UAC). They can duplicate the access token from "wusa.exe" to gain elevated privileges.
references:
    - https://www.fortinet.com/blog/threat-research/konni-campaign-distributed-via-malicious-document
author: X__Junior (Nextron Systems)
date: 2023-11-26
modified: 2024-08-15
tags:
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith: '\wusa.exe'
    selection_paths_1:
        ParentImage|contains:
            # Note: Add additional suspicious locations to increase coverage
            - ':\Perflogs\'
            - ':\Users\Public\'
            - ':\Windows\Temp\'
            - '\Appdata\Local\Temp\'
            - '\Temporary Internet'
    selection_paths_2:
        - ParentImage|contains|all:
              - ':\Users\'
              - '\Favorites\'
        - ParentImage|contains|all:
              - ':\Users\'
              - '\Favourites\'
        - ParentImage|contains|all:
              - ':\Users\'
              - '\Contacts\'
        - ParentImage|contains|all:
              - ':\Users\'
              - '\Pictures\'
    filter_main_msu:
        # Note: We exclude MSU extension files. A better approach is to baseline installation of updates in your env to avoid false negatives.
        CommandLine|contains: '.msu'
    condition: selection_img and 1 of selection_paths_* and not 1 of filter_main_*
falsepositives:
    - Unknown
level: high
```
