---
title: Malicious Windows Script Components File Execution by TAEF Detection
summary: |-
  Windows Test Authoring and Execution Framework (TAEF) framework allows you to run automation by executing tests files written on different languages (C, C#, Microsoft COM Scripting interfaces
  Adversaries may execute malicious code (such as WSC file with VBScript, dll and so on) directly by running te.exe
sigma_id: 634b00d5-ccc3-4a06-ae3b-0ec8444dd51b
status: test
level: low
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques:
  - T1218
author: Agro (@agro_sev) oscd.community
date: '2020-10-13'
modified: '2026-10-31'
falsepositives:
  - It's not an uncommon to use te.exe directly to execute legal TAEF tests
references:
  - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Te/
  - https://twitter.com/pabraeken/status/993298228840992768
  - https://learn.microsoft.com/en-us/windows-hardware/drivers/taef/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_susp_use_of_te_bin.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Malicious Windows Script Components File Execution by TAEF Detection
id: 634b00d5-ccc3-4a06-ae3b-0ec8444dd51b
status: test
description: |
  Windows Test Authoring and Execution Framework (TAEF) framework allows you to run automation by executing tests files written on different languages (C, C#, Microsoft COM Scripting interfaces
  Adversaries may execute malicious code (such as WSC file with VBScript, dll and so on) directly by running te.exe
references:
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Te/
    - https://twitter.com/pabraeken/status/993298228840992768
    - https://learn.microsoft.com/en-us/windows-hardware/drivers/taef/
author: 'Agro (@agro_sev) oscd.community'
date: 2020-10-13
modified: 2026-10-31
tags:
    - attack.stealth
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\te.exe'
        - ParentImage|endswith: '\te.exe'
        - OriginalFileName: 'te.exe'
    condition: selection
falsepositives:
    - It's not an uncommon to use te.exe directly to execute legal TAEF tests
level: low
```
