---
title: Suspicious Execution From Outlook Temporary Folder
summary: Detects a suspicious program execution in Outlook temp folder
sigma_id: a018fdc3-46a3-44e5-9afb-2cd4af1d4b39
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0001
techniques:
  - T1566.001
author: Florian Roth (Nextron Systems)
date: '2019-10-01'
modified: '2022-10-09'
falsepositives:
  - Unknown
references:
  - Internal Research
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_office_outlook_execution_from_temp.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Execution From Outlook Temporary Folder
id: a018fdc3-46a3-44e5-9afb-2cd4af1d4b39
status: test
description: Detects a suspicious program execution in Outlook temp folder
author: Florian Roth (Nextron Systems)
references:
    - Internal Research
date: 2019-10-01
modified: 2022-10-09
tags:
    - attack.initial-access
    - attack.t1566.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|contains: '\Temporary Internet Files\Content.Outlook\'
    condition: selection
falsepositives:
    - Unknown
level: high
```
