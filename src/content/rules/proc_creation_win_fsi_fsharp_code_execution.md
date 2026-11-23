---
title: Use of FSharp Interpreters
summary: |-
  Detects the execution of FSharp Interpreters "FsiAnyCpu.exe" and "FSi.exe"
  Both can be used for AWL bypass and to execute F# code via scripts or inline.
sigma_id: b96b2031-7c17-4473-afe7-a30ce714db29
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1059
author: Christopher Peacock @SecurePeacock, SCYTHE @scythe_io
date: '2022-06-02'
modified: '2024-04-23'
falsepositives:
  - Legitimate use by a software developer.
references:
  - https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/applications-that-can-bypass-wdac
  - https://bohops.com/2020/11/02/exploring-the-wdac-microsoft-recommended-block-rules-part-ii-wfc-fsi/
  - https://lolbas-project.github.io/lolbas/OtherMSBinaries/FsiAnyCpu/
  - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Fsi/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_fsi_fsharp_code_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Use of FSharp Interpreters
id: b96b2031-7c17-4473-afe7-a30ce714db29
status: test
description: |
    Detects the execution of FSharp Interpreters "FsiAnyCpu.exe" and "FSi.exe"
    Both can be used for AWL bypass and to execute F# code via scripts or inline.
references:
    - https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/applications-that-can-bypass-wdac
    - https://bohops.com/2020/11/02/exploring-the-wdac-microsoft-recommended-block-rules-part-ii-wfc-fsi/
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/FsiAnyCpu/
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Fsi/
author: Christopher Peacock @SecurePeacock, SCYTHE @scythe_io
date: 2022-06-02
modified: 2024-04-23
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith:
              - '\fsi.exe'
              - '\fsianycpu.exe'
        - OriginalFileName:
              - 'fsi.exe'
              - 'fsianycpu.exe'
    condition: selection
falsepositives:
    - Legitimate use by a software developer.
level: medium
```
