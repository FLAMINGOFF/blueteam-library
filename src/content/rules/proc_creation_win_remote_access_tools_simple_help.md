---
title: Remote Access Tool - Simple Help Execution
summary: >-
  An adversary may use legitimate desktop support and remote access software, such as Team Viewer, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and control channel to
  target systems within networks.

  These services are commonly used as legitimate technical support software, and may be allowed by application control within a target environment.

  Remote access tools like VNC, Ammyy, and Teamviewer are used frequently when compared with other legitimate software commonly used by adversaries. (Citation: Symantec Living off the Land)
sigma_id: 95e60a2b-4705-444b-b7da-ba0ea81a3ee2
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0011
techniques:
  - T1219.002
author: Nasreddine Bencherchali (Nextron Systems)
date: '2024-02-23'
falsepositives:
  - Legitimate usage of the tool
references:
  - https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_remote_access_tools_simple_help.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Remote Access Tool - Simple Help Execution
id: 95e60a2b-4705-444b-b7da-ba0ea81a3ee2
status: test
description: |
    An adversary may use legitimate desktop support and remote access software, such as Team Viewer, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and control channel to target systems within networks.
    These services are commonly used as legitimate technical support software, and may be allowed by application control within a target environment.
    Remote access tools like VNC, Ammyy, and Teamviewer are used frequently when compared with other legitimate software commonly used by adversaries. (Citation: Symantec Living off the Land)
references:
    - https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708
author: Nasreddine Bencherchali (Nextron Systems)
date: 2024-02-23
tags:
    - attack.command-and-control
    - attack.t1219.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|contains:
            - '\JWrapper-Remote Access\'
            - '\JWrapper-Remote Support\'
        Image|endswith: '\SimpleService.exe'
    condition: selection
falsepositives:
    - Legitimate usage of the tool
level: medium
```
