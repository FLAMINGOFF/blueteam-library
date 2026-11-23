---
title: Privilege Escalation via Named Pipe Impersonation
summary: Detects a remote file copy attempt to a hidden network share. This may indicate lateral movement or data staging activity.
sigma_id: 9bd04a79-dabe-4f1f-a5ff-92430265c96b
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0008
techniques:
  - T1021
author: Tim Rauch, Elastic (idea)
date: '2022-09-27'
modified: '2022-12-30'
falsepositives:
  - Other programs that cause these patterns (please report)
references:
  - https://www.elastic.co/guide/en/security/current/privilege-escalation-via-named-pipe-impersonation.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_susp_priv_escalation_via_named_pipe.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Privilege Escalation via Named Pipe Impersonation
id: 9bd04a79-dabe-4f1f-a5ff-92430265c96b
related:
    - id: f35c5d71-b489-4e22-a115-f003df287317
      type: derived
status: test
description: Detects a remote file copy attempt to a hidden network share. This may indicate lateral movement or data staging activity.
references:
    - https://www.elastic.co/guide/en/security/current/privilege-escalation-via-named-pipe-impersonation.html
author: Tim Rauch, Elastic (idea)
date: 2022-09-27
modified: 2022-12-30
tags:
    - attack.lateral-movement
    - attack.t1021
logsource:
    category: process_creation
    product: windows
detection:
    selection_name:
        - Image|endswith:
              - '\cmd.exe'
              - '\powershell.exe'
        - OriginalFileName:
              - 'Cmd.Exe'
              - 'PowerShell.EXE'
    selection_args:
        CommandLine|contains|all:
            - 'echo'
            - '>'
            - '\\\\.\\pipe\\'
    condition: all of selection*
falsepositives:
    - Other programs that cause these patterns (please report)
level: high
```
