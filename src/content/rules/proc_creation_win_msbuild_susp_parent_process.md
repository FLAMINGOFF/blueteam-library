---
title: Suspicious Msbuild Execution By Uncommon Parent Process
summary: Detects suspicious execution of 'Msbuild.exe' by a uncommon parent process
sigma_id: 33be4333-2c6b-44f4-ae28-102cdbde0a31
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques: []
author: frack113
date: '2022-11-17'
falsepositives:
  - Unknown
references:
  - https://app.any.run/tasks/abdf586e-df0c-4d39-89a7-06bf24913401/
  - https://www.echotrail.io/insights/search/msbuild.exe
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_msbuild_susp_parent_process.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Msbuild Execution By Uncommon Parent Process
id: 33be4333-2c6b-44f4-ae28-102cdbde0a31
status: test
description: Detects suspicious execution of 'Msbuild.exe' by a uncommon parent process
references:
    - https://app.any.run/tasks/abdf586e-df0c-4d39-89a7-06bf24913401/
    - https://www.echotrail.io/insights/search/msbuild.exe
author: frack113
date: 2022-11-17
tags:
    - attack.stealth
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\MSBuild.exe'
        - OriginalFileName: 'MSBuild.exe'
    filter_parent:
        ParentImage|endswith:
            - '\devenv.exe'
            - '\cmd.exe'
            - '\msbuild.exe'
            - '\python.exe'
            - '\explorer.exe'
            - '\nuget.exe'
    condition: selection and not filter_parent
falsepositives:
    - Unknown
level: medium
```
