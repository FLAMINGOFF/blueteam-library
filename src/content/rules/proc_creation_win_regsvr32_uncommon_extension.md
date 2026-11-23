---
title: Regsvr32 DLL Execution With Uncommon Extension
summary: Detects a "regsvr32" execution where the DLL doesn't contain a common file extension.
sigma_id: 50919691-7302-437f-8e10-1fe088afa145
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
  - TA0003
  - TA0002
techniques:
  - T1574
author: Florian Roth (Nextron Systems)
date: '2019-07-17'
modified: '2023-05-24'
falsepositives:
  - Other legitimate extensions currently not in the list either from third party or specific Windows components.
references:
  - https://app.any.run/tasks/34221348-072d-4b70-93f3-aa71f6ebecad/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_regsvr32_uncommon_extension.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Regsvr32 DLL Execution With Uncommon Extension
id: 50919691-7302-437f-8e10-1fe088afa145
status: test
description: Detects a "regsvr32" execution where the DLL doesn't contain a common file extension.
references:
    - https://app.any.run/tasks/34221348-072d-4b70-93f3-aa71f6ebecad/
author: Florian Roth (Nextron Systems)
date: 2019-07-17
modified: 2023-05-24
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.stealth
    - attack.t1574
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\regsvr32.exe'
        - OriginalFileName: 'REGSVR32.EXE'
    filter_main_legit_ext:
        CommandLine|contains:
            # Note: For better accuracy you might not want to use contains
            - '.ax'
            - '.cpl'
            - '.dll' # Covers ".dll.mui"
            - '.ocx'
    filter_optional_pascal:
        CommandLine|contains: '.ppl'
    filter_optional_avg:
        CommandLine|contains: '.bav'
    filter_main_null_4688:
        CommandLine: null
    filter_main_empty_4688:
        CommandLine: ''
    condition: selection and not 1 of filter_main_* and not 1 of filter_optional_*
falsepositives:
    - Other legitimate extensions currently not in the list either from third party or specific Windows components.
level: medium
```
