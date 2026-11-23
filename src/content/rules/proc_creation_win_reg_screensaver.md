---
title: Suspicious ScreenSave Change by Reg.exe
summary: |-
  Adversaries may establish persistence by executing malicious content triggered by user inactivity.
  Screensavers are programs that execute after a configurable time of user inactivity and consist of Portable Executable (PE) files with a .scr file extension
sigma_id: 0fc35fc3-efe6-4898-8a37-0b233339524f
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0003
  - TA0004
techniques:
  - T1546.002
author: frack113
date: '2021-08-19'
modified: '2022-06-02'
falsepositives:
  - GPO
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1546.002/T1546.002.md
  - https://www.welivesecurity.com/wp-content/uploads/2017/08/eset-gazer.pdf
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_reg_screensaver.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious ScreenSave Change by Reg.exe
id: 0fc35fc3-efe6-4898-8a37-0b233339524f
status: test
description: |
    Adversaries may establish persistence by executing malicious content triggered by user inactivity.
    Screensavers are programs that execute after a configurable time of user inactivity and consist of Portable Executable (PE) files with a .scr file extension
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1546.002/T1546.002.md
    - https://www.welivesecurity.com/wp-content/uploads/2017/08/eset-gazer.pdf
author: frack113
date: 2021-08-19
modified: 2022-06-02
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1546.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_reg:
        Image|endswith: '\reg.exe'
        CommandLine|contains:
            - 'HKEY_CURRENT_USER\Control Panel\Desktop'
            - 'HKCU\Control Panel\Desktop'
    selection_option_1: # /force Active ScreenSaveActive
        CommandLine|contains|all:
            - '/v ScreenSaveActive'
            - '/t REG_SZ'
            - '/d 1'
            - '/f'
    selection_option_2: # /force  set ScreenSaveTimeout
        CommandLine|contains|all:
            - '/v ScreenSaveTimeout'
            - '/t REG_SZ'
            - '/d '
            - '/f'
    selection_option_3: # /force set ScreenSaverIsSecure
        CommandLine|contains|all:
            - '/v ScreenSaverIsSecure'
            - '/t REG_SZ'
            - '/d 0'
            - '/f'
    selection_option_4: # /force set a .scr
        CommandLine|contains|all:
            - '/v SCRNSAVE.EXE'
            - '/t REG_SZ'
            - '/d '
            - '.scr'
            - '/f'
    condition: selection_reg and 1 of selection_option_*
falsepositives:
    - GPO
level: medium
```
