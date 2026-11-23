---
title: Potentially Suspicious Rundll32.EXE Execution of UDL File
summary: |-
  Detects the execution of rundll32.exe with the oledb32.dll library to open a UDL file.
  Threat actors can abuse this technique as a phishing vector to capture authentication credentials or other sensitive data.
sigma_id: 0ea52357-cd59-4340-9981-c46c7e900428
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
  - TA0011
techniques:
  - T1218.011
  - T1071
author: '@kostastsale'
date: '2024-08-16'
falsepositives:
  - UDL files serve as a convenient and flexible tool for managing and testing database connections in various development and administrative scenarios.
references:
  - https://trustedsec.com/blog/oops-i-udld-it-again
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_rundll32_udl_exec.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potentially Suspicious Rundll32.EXE Execution of UDL File
id: 0ea52357-cd59-4340-9981-c46c7e900428
status: test
description: |
    Detects the execution of rundll32.exe with the oledb32.dll library to open a UDL file.
    Threat actors can abuse this technique as a phishing vector to capture authentication credentials or other sensitive data.
references:
    - https://trustedsec.com/blog/oops-i-udld-it-again
author: '@kostastsale'
date: 2024-08-16
tags:
    - attack.execution
    - attack.command-and-control
    - attack.stealth
    - attack.t1218.011
    - attack.t1071
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\explorer.exe'
    selection_img:
        - Image|endswith: '\rundll32.exe'
        - OriginalFileName: 'RUNDLL32.EXE'
    selection_cli:
        CommandLine|contains|all:
            - 'oledb32.dll'
            - ',OpenDSLFile '
            - '\\Users\\*\\Downloads\\' # Note: You can adjust the path to the download directory or other directories according to your environment.
        CommandLine|endswith: '.udl'
    condition: all of selection_*
falsepositives:
    - UDL files serve as a convenient and flexible tool for managing and testing database connections in various development and administrative scenarios.
level: medium
```
