---
title: PDQ Deploy Remote Adminstartion Tool Execution
summary: Detect use of PDQ Deploy remote admin tool
sigma_id: d679950c-abb7-43a6-80fb-2a480c4fc450
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
  - TA0008
techniques:
  - T1072
author: frack113
date: '2022-10-01'
modified: '2023-01-30'
falsepositives:
  - Legitimate use
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/9e5b12c4912c07562aec7500447b11fa3e17e254/atomics/T1072/T1072.md
  - https://www.pdq.com/pdq-deploy/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_pdqdeploy_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: PDQ Deploy Remote Adminstartion Tool Execution
id: d679950c-abb7-43a6-80fb-2a480c4fc450
related:
    - id: 12b8e9f5-96b2-41e1-9a42-8c6779a5c184
      type: similar
status: test
description: Detect use of PDQ Deploy remote admin tool
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/9e5b12c4912c07562aec7500447b11fa3e17e254/atomics/T1072/T1072.md
    - https://www.pdq.com/pdq-deploy/
author: frack113
date: 2022-10-01
modified: 2023-01-30
tags:
    - attack.execution
    - attack.lateral-movement
    - attack.t1072
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Description: PDQ Deploy Console
        - Product: PDQ Deploy
        - Company: PDQ.com
        - OriginalFileName: PDQDeployConsole.exe
    condition: selection
falsepositives:
    - Legitimate use
level: medium
```
