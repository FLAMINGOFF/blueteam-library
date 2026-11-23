---
title: Nltest.EXE Execution
summary: Detects nltest commands that can be used for information discovery
sigma_id: 903076ff-f442-475a-b667-4f246bcc203b
status: test
level: low
platform: windows
logsource: windows / process_creation
tactics:
  - TA0007
techniques:
  - T1016
  - T1018
  - T1482
author: Arun Chauhan
date: '2023-02-03'
falsepositives:
  - Legitimate administration activity
references:
  - https://jpcertcc.github.io/ToolAnalysisResultSheet/details/nltest.htm
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_nltest_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Nltest.EXE Execution
id: 903076ff-f442-475a-b667-4f246bcc203b
related:
    - id: 5cc90652-4cbd-4241-aa3b-4b462fa5a248
      type: similar
    - id: eeb66bbb-3dde-4582-815a-584aee9fe6d1
      type: obsolete
status: test
description: Detects nltest commands that can be used for information discovery
references:
    - https://jpcertcc.github.io/ToolAnalysisResultSheet/details/nltest.htm
author: Arun Chauhan
date: 2023-02-03
tags:
    - attack.discovery
    - attack.t1016
    - attack.t1018
    - attack.t1482
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\nltest.exe'
        - OriginalFileName: 'nltestrk.exe'
    condition: selection
falsepositives:
    - Legitimate administration activity
level: low
```
