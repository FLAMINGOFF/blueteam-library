---
title: COM Object Execution via Xwizard.EXE
summary: |-
  Detects the execution of Xwizard tool with the "RunWizard" flag and a GUID like argument.
  This utility can be abused in order to run custom COM object created in the registry.
sigma_id: 53d4bb30-3f36-4e8a-b078-69d36c4a79ff
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques:
  - T1218
author: Ensar Şamil, @sblmsrsn, @oscd_initiative, Nasreddine Bencherchali (Nextron Systems)
date: '2020-10-07'
modified: '2026-11-05'
falsepositives:
  - Unknown
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Xwizard/
  - https://www.elastic.co/guide/en/security/current/execution-of-com-object-via-xwizard.html
  - https://www.hexacorn.com/blog/2017/07/31/the-wizard-of-x-oppa-plugx-style/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_xwizard_runwizard_com_object_exec.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: COM Object Execution via Xwizard.EXE
id: 53d4bb30-3f36-4e8a-b078-69d36c4a79ff
status: test
description: |
    Detects the execution of Xwizard tool with the "RunWizard" flag and a GUID like argument.
    This utility can be abused in order to run custom COM object created in the registry.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Xwizard/
    - https://www.elastic.co/guide/en/security/current/execution-of-com-object-via-xwizard.html
    - https://www.hexacorn.com/blog/2017/07/31/the-wizard-of-x-oppa-plugx-style/
author: Ensar Şamil, @sblmsrsn, @oscd_initiative, Nasreddine Bencherchali (Nextron Systems)
date: 2020-10-07
modified: 2026-11-05
tags:
    - attack.stealth
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\xwizard.exe'
        - OriginalFileName: 'xwizard.exe'
    selection_cli:
        CommandLine|contains: 'RunWizard'
        CommandLine|re: '\{[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}\}'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```
