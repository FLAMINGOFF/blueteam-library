---
title: Uncommon Svchost Parent Process
summary: Detects an uncommon svchost parent process
sigma_id: 01d2e2a1-5f09-44f7-9fc1-24faa7479b6d
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1036.005
author: Florian Roth (Nextron Systems)
date: '2017-08-15'
modified: '2026-10-19'
falsepositives:
  - Unknown
references:
  - Internal Research
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_svchost_uncommon_parent_process.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Uncommon Svchost Parent Process
id: 01d2e2a1-5f09-44f7-9fc1-24faa7479b6d
status: test
description: Detects an uncommon svchost parent process
references:
    - Internal Research
author: Florian Roth (Nextron Systems)
date: 2017-08-15
modified: 2026-10-19
tags:
    - attack.stealth
    - attack.t1036.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\svchost.exe'
    filter_main_generic:
        ParentImage|endswith:
            - '\Mrt.exe'
            - '\MsMpEng.exe'
            - '\ngen.exe'
            - '\rpcnet.exe'
            - '\services.exe'
            - '\TiWorker.exe'
    filter_main_svchost:
        ParentImage|endswith: '\svchost.exe'
        CommandLine|endswith:
            - 'svchost.exe"'
            - 'svchost.exe'
            - '-k TSLicensing'
    filter_main_parent_null:
        ParentImage: null
    filter_main_parent_empty:
        ParentImage:
            - '-'
            - ''
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: medium
```
