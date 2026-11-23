---
title: Group Membership Reconnaissance Via Whoami.EXE
summary: Detects the execution of whoami.exe with the /group command line flag to show group membership for the current user, account type, security identifiers (SID), and attributes.
sigma_id: bd8b828d-0dca-48e1-8a63-8a58ecf2644f
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0007
techniques:
  - T1033
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-02-28'
falsepositives:
  - Unknown
references:
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/whoami
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_whoami_groups_discovery.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Group Membership Reconnaissance Via Whoami.EXE
id: bd8b828d-0dca-48e1-8a63-8a58ecf2644f
status: test
description: Detects the execution of whoami.exe with the /group command line flag to show group membership for the current user, account type, security identifiers (SID), and attributes.
references:
    - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/whoami
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-02-28
tags:
    - attack.discovery
    - attack.t1033
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\whoami.exe'
        - OriginalFileName: 'whoami.exe'
    selection_cli:
        CommandLine|contains:
            - ' /groups'
            - ' -groups'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```
