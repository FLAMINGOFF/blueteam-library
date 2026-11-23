---
title: New Service Creation Using Sc.EXE
summary: Detects the creation of a new service using the "sc.exe" utility.
sigma_id: 85ff530b-261d-48c6-a441-facaa2e81e48
status: test
level: low
platform: windows
logsource: windows / process_creation
tactics:
  - TA0003
  - TA0004
techniques:
  - T1543.003
author: Timur Zinniatullin, Daniil Yugoslavskiy, oscd.community
date: '2023-02-20'
modified: '2025-09-01'
falsepositives:
  - Legitimate administrator or user creates a service for legitimate reasons.
  - Software installation
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1543.003/T1543.003.md
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_sc_create_service.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: New Service Creation Using Sc.EXE
id: 85ff530b-261d-48c6-a441-facaa2e81e48
related:
    - id: c02e96b7-c63a-4c47-bd83-4a9f74afcfb2 # Using PowerShell
      type: similar
status: test
description: Detects the creation of a new service using the "sc.exe" utility.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1543.003/T1543.003.md
author: Timur Zinniatullin, Daniil Yugoslavskiy, oscd.community
date: 2023-02-20
modified: 2025-09-01
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1543.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\sc.exe'
        CommandLine|contains|all:
            - 'create'
            - 'binPath'
    filter_optional_dropbox:
        ParentImage|startswith:
            - 'C:\Program Files (x86)\Dropbox\Client\'
            - 'C:\Program Files\Dropbox\Client\'
        ParentImage|endswith: '\Dropbox.exe'
    condition: selection and not 1 of filter_optional_*
falsepositives:
    - Legitimate administrator or user creates a service for legitimate reasons.
    - Software installation
level: low
```
