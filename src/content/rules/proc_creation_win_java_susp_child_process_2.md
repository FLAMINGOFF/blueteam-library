---
title: Shell Process Spawned by Java.EXE
summary: Detects shell spawned from Java host process, which could be a sign of exploitation (e.g. log4j exploitation)
sigma_id: dff1e1cc-d3fd-47c8-bfc2-aeb878a754c0
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0001
  - TA0003
  - TA0004
techniques: []
author: Andreas Hunkeler (@Karneades), Nasreddine Bencherchali
date: '2021-12-17'
modified: '2024-01-18'
falsepositives:
  - Legitimate calls to system binaries
  - Company specific internal usage
references:
  - https://web.archive.org/web/20231230220738/https://www.lunasec.io/docs/blog/log4j-zero-day/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_java_susp_child_process_2.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Shell Process Spawned by Java.EXE
id: dff1e1cc-d3fd-47c8-bfc2-aeb878a754c0
related:
    - id: 0d34ed8b-1c12-4ff2-828c-16fc860b766d
      type: similar
status: test
description: Detects shell spawned from Java host process, which could be a sign of exploitation (e.g. log4j exploitation)
references:
    - https://web.archive.org/web/20231230220738/https://www.lunasec.io/docs/blog/log4j-zero-day/
author: Andreas Hunkeler (@Karneades), Nasreddine Bencherchali
date: 2021-12-17
modified: 2024-01-18
tags:
    - attack.initial-access
    - attack.persistence
    - attack.privilege-escalation
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\java.exe'
        Image|endswith:
            - '\bash.exe'
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
    filter_main_build:
        ParentImage|contains: 'build'  # excluding CI build agents
        CommandLine|contains: 'build'  # excluding CI build agents
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Legitimate calls to system binaries
    - Company specific internal usage
level: medium
```
