---
title: Remote Access Tool - NetSupport Execution
summary: >-
  An adversary may use legitimate desktop support and remote access software, such as Team Viewer, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and control channel to
  target systems within networks.

  These services are commonly used as legitimate technical support software, and may be allowed by application control within a target environment.

  Remote access tools like VNC, Ammyy, and Teamviewer are used frequently when compared with other legitimate software commonly used by adversaries. (Citation: Symantec Living off the Land)
sigma_id: 758ff488-18d5-4cbe-8ec4-02b6285a434f
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0011
techniques:
  - T1219.002
author: frack113
date: '2022-09-25'
modified: '2023-03-06'
falsepositives:
  - Legitimate use
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1219/T1219.md
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_remote_access_tools_netsupport.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Remote Access Tool - NetSupport Execution
id: 758ff488-18d5-4cbe-8ec4-02b6285a434f
status: test
description: |
    An adversary may use legitimate desktop support and remote access software, such as Team Viewer, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and control channel to target systems within networks.
    These services are commonly used as legitimate technical support software, and may be allowed by application control within a target environment.
    Remote access tools like VNC, Ammyy, and Teamviewer are used frequently when compared with other legitimate software commonly used by adversaries. (Citation: Symantec Living off the Land)
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1219/T1219.md
author: frack113
date: 2022-09-25
modified: 2023-03-06
tags:
    - attack.command-and-control
    - attack.t1219.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Description: NetSupport Client Configurator
        - Product: NetSupport Remote Control
        - Company: NetSupport Ltd
        - OriginalFileName: PCICFGUI.EXE
    condition: selection
falsepositives:
    - Legitimate use
level: medium
```
