---
title: Uncommon Child Process Of Conhost.EXE
summary: Detects uncommon "conhost" child processes. This could be a sign of "conhost" usage as a LOLBIN or potential process injection activity.
sigma_id: 7dc2dedd-7603-461a-bc13-15803d132355
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1202
author: omkar72
date: '2020-10-25'
modified: '2023-12-11'
falsepositives:
  - Unknown
references:
  - http://www.hexacorn.com/blog/2020/05/25/how-to-con-your-host/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_conhost_susp_child_process.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Uncommon Child Process Of Conhost.EXE
id: 7dc2dedd-7603-461a-bc13-15803d132355
related:
    - id: dfa03a09-8b92-4d83-8e74-f72839b1c407
      type: similar
status: test
description: Detects uncommon "conhost" child processes. This could be a sign of "conhost" usage as a LOLBIN or potential process injection activity.
references:
    - http://www.hexacorn.com/blog/2020/05/25/how-to-con-your-host/
author: omkar72
date: 2020-10-25
modified: 2023-12-11
tags:
    - attack.stealth
    - attack.t1202
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\conhost.exe'
    filter_main_conhost:
        Image|endswith: ':\Windows\System32\conhost.exe'
    filter_main_null:
        Image: null
    filter_main_empty:
        Image: ''
    filter_optional_provider:
        Provider_Name: 'SystemTraceProvider-Process'  # Race condition with SystemTrace doesn't provide all fields.
    condition: selection and not 1 of filter_main_* and not 1 of filter_optional_*
falsepositives:
    - Unknown
level: medium
```
