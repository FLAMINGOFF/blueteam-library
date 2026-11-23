---
title: Potential CommandLine Path Traversal Via Cmd.EXE
summary: Detects potential path traversal attempt via cmd.exe. Could indicate possible command/argument confusion/hijacking
sigma_id: 087790e3-3287-436c-bccf-cbd0184a7db1
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1059.003
author: xknow @xknow_infosec, Tim Shelton
date: '2020-06-11'
modified: '2023-03-06'
falsepositives:
  - Java tools are known to produce false-positive when loading libraries
references:
  - https://hackingiscool.pl/cmdhijack-command-argument-confusion-with-path-traversal-in-cmd-exe/
  - https://twitter.com/Oddvarmoe/status/1270633613449723905
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_cmd_path_traversal.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential CommandLine Path Traversal Via Cmd.EXE
id: 087790e3-3287-436c-bccf-cbd0184a7db1
status: test
description: Detects potential path traversal attempt via cmd.exe. Could indicate possible command/argument confusion/hijacking
references:
    - https://hackingiscool.pl/cmdhijack-command-argument-confusion-with-path-traversal-in-cmd-exe/
    - https://twitter.com/Oddvarmoe/status/1270633613449723905
author: xknow @xknow_infosec, Tim Shelton
date: 2020-06-11
modified: 2023-03-06
tags:
    - attack.execution
    - attack.t1059.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - ParentImage|endswith: '\cmd.exe'
        - Image|endswith: '\cmd.exe'
        - OriginalFileName: 'cmd.exe'
    selection_flags:
        - ParentCommandLine|contains:
              - '/c'
              - '/k'
              - '/r'
        - CommandLine|contains:
              - '/c'
              - '/k'
              - '/r'
    selection_path_traversal:
        - ParentCommandLine: '/../../'
        - CommandLine|contains: '/../../'
    filter_java:
        CommandLine|contains: '\Tasktop\keycloak\bin\/../../jre\bin\java'
    condition: all of selection_* and not 1 of filter_*
falsepositives:
    - Java tools are known to produce false-positive when loading libraries
level: high
```
