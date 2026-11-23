---
title: Remote Access Tool - ScreenConnect Remote Command Execution
summary: Detects the execution of a system command via the ScreenConnect RMM service.
sigma_id: b1f73849-6329-4069-bc8f-78a604bb8b23
status: test
level: low
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1059.003
author: Ali Alwashali
date: '2023-10-10'
modified: '2024-02-26'
falsepositives:
  - Legitimate use of ScreenConnect. Disable this rule if ScreenConnect is heavily used.
references:
  - https://github.com/SigmaHQ/sigma/pull/4467
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_remote_access_tools_screenconnect_remote_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Remote Access Tool - ScreenConnect Remote Command Execution
id: b1f73849-6329-4069-bc8f-78a604bb8b23
status: test
description: Detects the execution of a system command via the ScreenConnect RMM service.
references:
    - https://github.com/SigmaHQ/sigma/pull/4467
author: Ali Alwashali
date: 2023-10-10
modified: 2024-02-26
tags:
    - attack.execution
    - attack.t1059.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\ScreenConnect.ClientService.exe'
    selection_img:
        - Image|endswith: '\cmd.exe'
        - OriginalFileName: 'Cmd.Exe'
    selection_cli:
        # Example:
        #   CommandLine: "cmd.exe" /c "C:\Windows\TEMP\ScreenConnect\23.6.8.8644\3c41d689-bbf5-4216-b2f4-ba8fd6192c25run.cmd"
        CommandLine|contains: '\TEMP\ScreenConnect\'
    condition: all of selection_*
falsepositives:
    - Legitimate use of ScreenConnect. Disable this rule if ScreenConnect is heavily used.
# Note: Increase the level if you don't leverage ScreenConnect
level: low
```
